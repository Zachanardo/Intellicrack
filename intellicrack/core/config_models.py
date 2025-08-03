"""
Pydantic Configuration Models for Intellicrack

Provides type-safe configuration validation with environment variable support
and comprehensive validation rules for all configuration sections.

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

import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseSettings
    SettingsConfigDict = dict


class LogLevel(str, Enum):
    """Supported logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class UITheme(str, Enum):
    """UI theme options."""
    DARK = "dark"
    LIGHT = "light"
    AUTO = "auto"


class Environment(str, Enum):
    """Application environment types."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class ModelProvider(str, Enum):
    """AI model provider options."""
    AUTO = "auto"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    DISABLED = "disabled"


def parse_memory_size(value: str) -> int:
    """Parse memory size string to bytes."""
    if isinstance(value, int):
        return value

    value = str(value).upper().strip()

    # Extract number and unit
    match = re.match(r'(\d+(?:\.\d+)?)\s*([KMGT]?B?)', value)
    if not match:
        raise ValueError(f"Invalid memory size format: {value}")

    size, unit = match.groups()
    size = float(size)

    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4,
        '': 1024 ** 2  # Default to MB
    }

    multiplier = multipliers.get(unit, multipliers['MB'])
    return int(size * multiplier)


class DirectoriesConfig(BaseModel):
    """Configuration for application directories."""

    config: Path = Field(
        description="Main configuration directory"
    )
    output: Path = Field(
        description="Output directory for analysis results"
    )
    logs: Path = Field(
        description="Log files directory"
    )
    cache: Path = Field(
        description="Cache directory for temporary files"
    )
    temp: Path = Field(
        description="Temporary files directory"
    )

    @field_validator('config', 'output', 'logs', 'cache', 'temp')
    @classmethod
    def validate_directory_path(cls, v: Union[str, Path]) -> Path:
        """Ensure directory paths are valid Path objects."""
        return Path(v).expanduser().resolve()

    @model_validator(mode='after')
    def create_directories(self) -> 'DirectoriesConfig':
        """Create directories if they don't exist."""
        for _field_name, path in self:
            if isinstance(path, Path):
                try:
                    path.mkdir(parents=True, exist_ok=True)
                except (OSError, PermissionError) as e:
                    # Log warning but don't fail validation
                    import logging
                    logging.getLogger(__name__).warning(
                        f"Could not create directory {path}: {e}"
                    )
        return self


class ToolConfig(BaseModel):
    """Configuration for a single external tool."""

    available: bool = Field(
        default=False,
        description="Whether the tool is available and validated"
    )
    path: Optional[Path] = Field(
        default=None,
        description="Full path to the tool executable"
    )
    version: Optional[str] = Field(
        default=None,
        description="Detected version of the tool"
    )
    auto_discovered: bool = Field(
        default=True,
        description="Whether the tool was auto-discovered or manually configured"
    )
    last_check: Optional[float] = Field(
        default=None,
        description="Timestamp of last validation check"
    )
    required_version: Optional[str] = Field(
        default=None,
        description="Minimum required version"
    )

    @field_validator('path')
    @classmethod
    def validate_tool_path(cls, v: Optional[Union[str, Path]]) -> Optional[Path]:
        """Validate tool path exists if provided."""
        if v is None:
            return None

        path = Path(v).expanduser().resolve()
        if not path.exists():
            import logging
            logging.getLogger(__name__).warning(
                f"Tool path does not exist: {path}"
            )
        return path


class ToolsConfig(BaseModel):
    """Configuration for all external tools."""

    ghidra: ToolConfig = Field(default_factory=ToolConfig)
    radare2: ToolConfig = Field(default_factory=ToolConfig)
    python3: ToolConfig = Field(default_factory=ToolConfig)
    frida: ToolConfig = Field(default_factory=ToolConfig)
    qemu: ToolConfig = Field(default_factory=ToolConfig)
    java: ToolConfig = Field(default_factory=ToolConfig)
    die: ToolConfig = Field(default_factory=ToolConfig)


class PreferencesConfig(BaseModel):
    """User preferences configuration."""

    auto_update_signatures: bool = Field(
        default=True,
        description="Automatically update signature databases"
    )
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Application logging level"
    )
    parallel_analysis: bool = Field(
        default=True,
        description="Enable parallel analysis processing"
    )
    max_analysis_threads: int = Field(
        default_factory=lambda: os.cpu_count() or 4,
        ge=1,
        le=32,
        description="Maximum number of analysis threads"
    )
    auto_backup_results: bool = Field(
        default=True,
        description="Automatically backup analysis results"
    )
    ui_theme: UITheme = Field(
        default=UITheme.DARK,
        description="UI theme preference"
    )
    check_for_updates: bool = Field(
        default=True,
        description="Check for application updates"
    )


class AnalysisConfig(BaseModel):
    """Analysis engine configuration."""

    default_timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Default analysis timeout in seconds"
    )
    max_memory_usage: str = Field(
        default="2GB",
        description="Maximum memory usage for analysis"
    )
    enable_ml_analysis: bool = Field(
        default=True,
        description="Enable machine learning analysis features"
    )
    enable_ai_features: bool = Field(
        default=True,
        description="Enable AI-powered analysis features"
    )
    save_intermediate_results: bool = Field(
        default=True,
        description="Save intermediate analysis results"
    )

    @field_validator('max_memory_usage')
    @classmethod
    def validate_memory_usage(cls, v: str) -> str:
        """Validate memory usage string format."""
        try:
            parse_memory_size(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid memory usage format: {e}") from e


class NetworkConfig(BaseModel):
    """Network configuration."""

    proxy_enabled: bool = Field(
        default=False,
        description="Enable proxy for network requests"
    )
    proxy_host: str = Field(
        default="",
        description="Proxy server hostname"
    )
    proxy_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Proxy server port"
    )
    ssl_verify: bool = Field(
        default=True,
        description="Verify SSL certificates"
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Network request timeout in seconds"
    )

    @field_validator('proxy_host')
    @classmethod
    def validate_proxy_host(cls, v: str) -> str:
        """Validate proxy host format."""
        v = v.strip()
        if v and not (v.startswith('http://') or v.startswith('https://') or
                     re.match(r'^[\w\.-]+$', v)):
            raise ValueError("Invalid proxy host format")
        return v


class SecurityConfig(BaseModel):
    """Security configuration."""

    sandbox_analysis: bool = Field(
        default=True,
        description="Run analysis in sandboxed environment"
    )
    allow_network_access: bool = Field(
        default=False,
        description="Allow network access during analysis"
    )
    log_sensitive_data: bool = Field(
        default=False,
        description="Log potentially sensitive data"
    )
    encrypt_config: bool = Field(
        default=False,
        description="Encrypt configuration files"
    )
    max_file_size: str = Field(
        default="100MB",
        description="Maximum file size for analysis"
    )

    @field_validator('max_file_size')
    @classmethod
    def validate_max_file_size(cls, v: str) -> str:
        """Validate file size format."""
        try:
            parse_memory_size(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid file size format: {e}") from e


class PatchingConfig(BaseModel):
    """Binary patching configuration."""

    backup_original: bool = Field(
        default=True,
        description="Create backup of original files before patching"
    )
    verify_patches: bool = Field(
        default=True,
        description="Verify patches after application"
    )
    max_patch_size: str = Field(
        default="10MB",
        description="Maximum size for individual patches"
    )
    patch_format: str = Field(
        default="binary",
        pattern=r"^(binary|text|unified)$",
        description="Default patch format"
    )

    @field_validator('max_patch_size')
    @classmethod
    def validate_patch_size(cls, v: str) -> str:
        """Validate patch size format."""
        try:
            parse_memory_size(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid patch size format: {e}") from e


class UIConfig(BaseModel):
    """User interface configuration."""

    theme: UITheme = Field(
        default=UITheme.DARK,
        description="UI theme"
    )
    font_size: int = Field(
        default=10,
        ge=8,
        le=24,
        description="UI font size"
    )
    show_tooltips: bool = Field(
        default=True,
        description="Show helpful tooltips"
    )
    auto_save_layout: bool = Field(
        default=True,
        description="Automatically save window layout"
    )
    hex_view_columns: int = Field(
        default=16,
        ge=8,
        le=32,
        description="Number of columns in hex view"
    )


class AIConfig(BaseModel):
    """AI features configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable AI features"
    )
    model_provider: ModelProvider = Field(
        default=ModelProvider.AUTO,
        description="AI model provider"
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="AI model temperature"
    )
    max_tokens: int = Field(
        default=2048,
        ge=100,
        le=32000,
        description="Maximum tokens per AI request"
    )
    cache_responses: bool = Field(
        default=True,
        description="Cache AI responses for similar queries"
    )
    background_loading: bool = Field(
        default=True,
        description="Load AI models in background"
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key for external AI services"
    )

    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        """Validate API key format."""
        if v:
            v = v.strip()
            if len(v) < 10:
                raise ValueError("API key appears to be too short")
        return v


class IntellicrackSettings(BaseSettings):
    """Main Intellicrack configuration with environment variable support."""

    model_config = SettingsConfigDict(
        env_prefix='INTELLICRACK_',
        env_nested_delimiter='_',
        case_sensitive=False,
        extra='allow',
        validate_assignment=True
    )

    version: str = Field(
        default="2.0",
        description="Configuration version"
    )
    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Application environment"
    )
    platform: str = Field(
        default=sys.platform,
        description="Operating system platform"
    )

    directories: DirectoriesConfig
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    preferences: PreferencesConfig = Field(default_factory=PreferencesConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    patching: PatchingConfig = Field(default_factory=PatchingConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

    # Metadata fields
    created: Optional[str] = Field(default=None, description="Creation timestamp")
    emergency_mode: bool = Field(default=False, description="Emergency mode flag")
    tool_validation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Tool validation results"
    )

    def __init__(self, **data):
        """Initialize settings with environment variable support."""
        super().__init__(**data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntellicrackSettings':
        """Create settings from dictionary (for backward compatibility)."""
        return cls(**data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (for backward compatibility)."""
        return self.model_dump(mode='json', by_alias=True)

    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update settings from dictionary."""
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @model_validator(mode='after')
    def validate_configuration(self) -> 'IntellicrackSettings':
        """Perform cross-field validation."""
        # Validate AI configuration
        if self.ai.enabled and self.ai.model_provider != ModelProvider.LOCAL:
            if not self.ai.api_key and self.ai.model_provider != ModelProvider.AUTO:
                import logging
                logging.getLogger(__name__).warning(
                    f"AI enabled with {self.ai.model_provider} provider but no API key provided"
                )

        # Validate security settings
        if self.security.allow_network_access and self.security.sandbox_analysis:
            import logging
            logging.getLogger(__name__).warning(
                "Network access enabled in sandbox mode - consider security implications"
            )

        # Validate analysis settings
        if self.analysis.enable_ai_features and not self.ai.enabled:
            import logging
            logging.getLogger(__name__).warning(
                "AI analysis features enabled but AI system is disabled"
            )

        return self


def create_default_directories_config() -> DirectoriesConfig:
    """Create default directories configuration based on platform."""
    import os
    import sys
    from pathlib import Path

    if sys.platform == "win32":
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
        config_dir = Path(base) / 'Intellicrack'
    elif sys.platform == "darwin":
        config_dir = Path.home() / 'Library' / 'Application Support' / 'Intellicrack'
    else:
        xdg_config = os.environ.get('XDG_CONFIG_HOME', '~/.config')
        config_dir = Path(xdg_config).expanduser() / 'intellicrack'

    temp_dir = Path.home() / 'tmp' if sys.platform != 'win32' else Path.home() / 'AppData' / 'Local' / 'Temp'

    return DirectoriesConfig(
        config=config_dir,
        output=config_dir / 'output',
        logs=config_dir / 'logs',
        cache=config_dir / 'cache',
        temp=temp_dir
    )
