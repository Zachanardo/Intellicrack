"""
Environment Variable Configuration Support for Intellicrack

Handles loading configuration from environment variables with proper precedence
and type conversion for Pydantic models.

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
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger(__name__)


class EnvironmentConfigLoader:
    """
    Loads configuration from environment variables with proper precedence.
    
    Environment variable naming convention:
    - Prefix: INTELLICRACK_
    - Nested fields: INTELLICRACK_SECTION_FIELD
    - Deep nesting: INTELLICRACK_SECTION_SUBSECTION_FIELD
    
    Examples:
    - INTELLICRACK_ANALYSIS_DEFAULT_TIMEOUT=600
    - INTELLICRACK_TOOLS_GHIDRA_PATH=/opt/ghidra
    - INTELLICRACK_AI_MODEL_PROVIDER=openai
    """

    ENV_PREFIX = "INTELLICRACK_"

    def __init__(self):
        """Initialize environment loader."""
        self._env_vars = self._load_intellicrack_env_vars()

    def _load_intellicrack_env_vars(self) -> Dict[str, str]:
        """Load all Intellicrack environment variables."""
        env_vars = {}

        for key, value in os.environ.items():
            if key.startswith(self.ENV_PREFIX):
                # Remove prefix and store
                config_key = key[len(self.ENV_PREFIX):]
                env_vars[config_key.lower()] = value

        logger.debug(f"Loaded {len(env_vars)} environment variables")
        return env_vars

    def get_nested_value(self, key_path: str) -> Optional[str]:
        """
        Get environment variable value by nested key path.
        
        Args:
            key_path: Dot-separated key path (e.g., 'analysis.default_timeout')
            
        Returns:
            Environment variable value or None
        """
        # Convert dot notation to underscore notation
        env_key = key_path.replace('.', '_').lower()
        return self._env_vars.get(env_key)

    def apply_env_overrides(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration dictionary.
        
        Args:
            config_dict: Base configuration dictionary
            
        Returns:
            Updated configuration dictionary with environment overrides
        """
        result = config_dict.copy()

        for env_key, env_value in self._env_vars.items():
            try:
                # Convert environment key to nested dict path
                key_parts = env_key.split('_')
                self._set_nested_value(result, key_parts, env_value)
                logger.debug(f"Applied environment override: {env_key} = {env_value}")

            except Exception as e:
                logger.warning(f"Failed to apply environment override {env_key}: {e}")

        return result

    def _set_nested_value(self, config_dict: Dict[str, Any], key_parts: list, value: str) -> None:
        """
        Set nested dictionary value from key parts and string value.
        
        Args:
            config_dict: Dictionary to update
            key_parts: List of key parts for nesting
            value: String value to convert and set
        """
        if not key_parts:
            return

        # Navigate to the parent dictionary
        current = config_dict
        for part in key_parts[:-1]:
            if part not in current:
                current[part] = {}
            elif not isinstance(current[part], dict):
                # Can't navigate further - key conflicts with existing value
                logger.warning(f"Cannot apply environment override - key conflict at {part}")
                return
            current = current[part]

        # Set the final value with type conversion
        final_key = key_parts[-1]
        converted_value = self._convert_env_value(value, current.get(final_key))
        current[final_key] = converted_value

    def _convert_env_value(self, env_value: str, existing_value: Any = None) -> Any:
        """
        Convert environment variable string to appropriate type.
        
        Args:
            env_value: String value from environment
            existing_value: Existing value to infer type from
            
        Returns:
            Converted value with appropriate type
        """
        # Handle boolean values
        if env_value.lower() in ('true', 'yes', '1', 'on'):
            return True
        elif env_value.lower() in ('false', 'no', '0', 'off'):
            return False

        # Handle null/none values
        if env_value.lower() in ('null', 'none', ''):
            return None

        # Try to infer type from existing value
        if existing_value is not None:
            try:
                if isinstance(existing_value, bool):
                    return env_value.lower() in ('true', 'yes', '1', 'on')
                elif isinstance(existing_value, int):
                    return int(env_value)
                elif isinstance(existing_value, float):
                    return float(env_value)
                elif isinstance(existing_value, Path):
                    return Path(env_value)
                elif isinstance(existing_value, list):
                    # Try to parse as JSON list, fallback to comma-separated
                    try:
                        return json.loads(env_value)
                    except json.JSONDecodeError:
                        return [item.strip() for item in env_value.split(',') if item.strip()]
                elif isinstance(existing_value, dict):
                    # Parse as JSON
                    return json.loads(env_value)
            except (ValueError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to convert environment value '{env_value}' to type {type(existing_value)}: {e}")

        # Try intelligent type conversion
        # Integer
        try:
            if '.' not in env_value:
                return int(env_value)
        except ValueError:
            pass

        # Float
        try:
            return float(env_value)
        except ValueError:
            pass

        # JSON
        try:
            return json.loads(env_value)
        except json.JSONDecodeError:
            pass

        # Path (if it looks like a path)
        if ('/' in env_value or '\\' in env_value or env_value.startswith('~')):
            return Path(env_value)

        # Default to string
        return env_value

    def get_environment_profile(self) -> str:
        """
        Get the current environment profile.
        
        Returns:
            Environment profile (development, staging, production)
        """
        return os.environ.get('INTELLICRACK_ENVIRONMENT', 'development').lower()

    def load_environment_specific_config(self, base_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Load environment-specific configuration overrides.
        
        Args:
            base_config: Base configuration dictionary
            
        Returns:
            Configuration with environment-specific overrides applied
        """
        env_profile = self.get_environment_profile()
        config = base_config.copy()

        # Apply environment-specific settings
        if env_profile == 'development':
            config = self._apply_development_overrides(config)
        elif env_profile == 'staging':
            config = self._apply_staging_overrides(config)
        elif env_profile == 'production':
            config = self._apply_production_overrides(config)

        logger.info(f"Applied {env_profile} environment configuration")
        return config

    def _apply_development_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply development environment overrides."""
        config = config.copy()

        # Development-friendly settings
        if 'preferences' in config:
            config['preferences'].update({
                'log_level': 'DEBUG',
                'auto_backup_results': False,
                'check_for_updates': False
            })

        if 'security' in config:
            config['security'].update({
                'log_sensitive_data': True,
                'sandbox_analysis': False  # Less restrictive for development
            })

        if 'analysis' in config:
            config['analysis'].update({
                'default_timeout': 600,  # Longer timeout for debugging
                'save_intermediate_results': True
            })

        return config

    def _apply_staging_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply staging environment overrides."""
        config = config.copy()

        # Staging-specific settings
        if 'preferences' in config:
            config['preferences'].update({
                'log_level': 'INFO',
                'auto_backup_results': True,
                'check_for_updates': False
            })

        if 'security' in config:
            config['security'].update({
                'log_sensitive_data': False,
                'sandbox_analysis': True
            })

        return config

    def _apply_production_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply production environment overrides."""
        config = config.copy()

        # Production-optimized settings
        if 'preferences' in config:
            config['preferences'].update({
                'log_level': 'WARNING',
                'auto_backup_results': True,
                'check_for_updates': True
            })

        if 'security' in config:
            config['security'].update({
                'log_sensitive_data': False,
                'sandbox_analysis': True,
                'allow_network_access': False
            })

        if 'analysis' in config:
            config['analysis'].update({
                'default_timeout': 300,  # Conservative timeout
                'save_intermediate_results': False  # Save space
            })

        return config

    def validate_required_env_vars(self) -> Dict[str, str]:
        """
        Validate that required environment variables are set.
        
        Returns:
            Dictionary of missing required environment variables
        """
        required_vars = {
            # Add any required environment variables here
            # 'INTELLICRACK_API_KEY': 'AI API key for external services'
        }

        missing_vars = {}
        for var_name, description in required_vars.items():
            if var_name not in os.environ:
                missing_vars[var_name] = description

        if missing_vars:
            logger.warning(f"Missing required environment variables: {list(missing_vars.keys())}")

        return missing_vars

    def get_all_env_overrides(self) -> Dict[str, str]:
        """
        Get all Intellicrack environment variable overrides.
        
        Returns:
            Dictionary of all environment variable overrides
        """
        return self._env_vars.copy()

    def export_env_template(self, file_path: Union[str, Path]) -> None:
        """
        Export environment variable template file.
        
        Args:
            file_path: Path to write the template file
        """
        template_content = [
            "# Intellicrack Environment Variables Template",
            "# Copy to .env or set in your shell environment",
            "",
            "# Application Environment (development/staging/production)",
            "INTELLICRACK_ENVIRONMENT=development",
            "",
            "# Directories",
            "# INTELLICRACK_DIRECTORIES_OUTPUT=/path/to/output",
            "# INTELLICRACK_DIRECTORIES_CACHE=/path/to/cache",
            "",
            "# Tools",
            "# INTELLICRACK_TOOLS_GHIDRA_PATH=/opt/ghidra",
            "# INTELLICRACK_TOOLS_RADARE2_PATH=/usr/bin/r2",
            "",
            "# Analysis Settings",
            "# INTELLICRACK_ANALYSIS_DEFAULT_TIMEOUT=600",
            "# INTELLICRACK_ANALYSIS_MAX_MEMORY_USAGE=4GB",
            "",
            "# AI Configuration",
            "# INTELLICRACK_AI_ENABLED=true",
            "# INTELLICRACK_AI_MODEL_PROVIDER=openai",
            "# INTELLICRACK_AI_API_KEY=your_api_key_here",
            "",
            "# Network Settings",
            "# INTELLICRACK_NETWORK_PROXY_ENABLED=false",
            "# INTELLICRACK_NETWORK_PROXY_HOST=proxy.example.com",
            "# INTELLICRACK_NETWORK_PROXY_PORT=8080",
            "",
            "# Security Settings",
            "# INTELLICRACK_SECURITY_SANDBOX_ANALYSIS=true",
            "# INTELLICRACK_SECURITY_ALLOW_NETWORK_ACCESS=false",
            "",
            "# UI Settings",
            "# INTELLICRACK_UI_THEME=dark",
            "# INTELLICRACK_UI_FONT_SIZE=10",
            "",
            "# Preferences",
            "# INTELLICRACK_PREFERENCES_LOG_LEVEL=INFO",
            "# INTELLICRACK_PREFERENCES_MAX_ANALYSIS_THREADS=4",
            ""
        ]

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(template_content))

        logger.info(f"Environment variable template exported to {file_path}")


def load_dotenv_file(env_file: Union[str, Path] = ".env") -> None:
    """
    Load environment variables from .env file if it exists.
    
    Args:
        env_file: Path to .env file
    """
    env_path = Path(env_file)
    if not env_path.exists():
        return

    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse KEY=VALUE format
                if '=' not in line:
                    logger.warning(f"Invalid line in {env_file}:{line_num}: {line}")
                    continue

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]

                # Set environment variable if not already set
                if key not in os.environ:
                    os.environ[key] = value
                    logger.debug(f"Loaded from .env: {key}")

        logger.info(f"Loaded environment variables from {env_file}")

    except Exception as e:
        logger.error(f"Failed to load .env file {env_file}: {e}")


# Global instance
_env_loader = None


def get_env_loader() -> EnvironmentConfigLoader:
    """Get global environment loader instance."""
    global _env_loader
    if _env_loader is None:
        _env_loader = EnvironmentConfigLoader()
    return _env_loader
