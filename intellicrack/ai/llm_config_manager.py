"""
LLM Configuration Manager for Intellicrack

Dynamic configuration management for all LLM providers with runtime updates,
validation, migration, and secure API key management.

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

import asyncio
import copy
import hashlib
import json
import os
import shutil
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor

from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, validator
import yaml

from ..utils.logger import get_logger
from ..utils.secrets_manager import get_secret, set_secret
from .llm_backends import LLMConfig, LLMProvider, get_llm_manager

logger = get_logger(__name__)
class ConfigurationProfile(str, Enum):
    """Configuration profiles for different environments."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"
    CUSTOM = "custom"


class ConfigChangeType(str, Enum):
    """Types of configuration changes."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ROLLBACK = "rollback"
    IMPORT = "import"
    EXPORT = "export"


class ProviderConfig(BaseModel):
    """Configuration for a single LLM provider."""
    provider: LLMProvider
    api_key: Optional[str] = Field(None, description="Encrypted API key")
    api_base: Optional[str] = Field(None, description="Custom API endpoint")
    rate_limit: Optional[int] = Field(None, description="Requests per minute")
    timeout: Optional[int] = Field(30, description="Request timeout in seconds")
    retry_attempts: Optional[int] = Field(3, description="Number of retry attempts")
    custom_headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    enabled: bool = Field(True, description="Whether provider is enabled")
    
    @validator('api_key')
    def validate_api_key(cls, v):
        """Validate API key format."""
        if v and not v.startswith("sk-") and not v.startswith("enc:"):
            if len(v) < 20:
                raise ValueError("API key appears to be invalid")
        return v
class ModelSettings(BaseModel):
    """Settings for a specific model."""
    model_name: str
    provider: LLMProvider
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(2048, ge=1, le=32768)
    top_p: float = Field(0.95, ge=0.0, le=1.0)
    frequency_penalty: float = Field(0.0, ge=-2.0, le=2.0)
    presence_penalty: float = Field(0.0, ge=-2.0, le=2.0)
    context_length: int = Field(4096, ge=1)
    tools_enabled: bool = Field(True)
    cache_enabled: bool = Field(True)
    cache_ttl: int = Field(3600, description="Cache time-to-live in seconds")
    cost_per_1k_tokens: Optional[float] = Field(None, description="Cost tracking")
    
    @validator('model_name')
    def validate_model_name(cls, v):
        """Validate model name format."""
        if not v or not v.strip():
            raise ValueError("Model name cannot be empty")
        return v.strip()


class CostControl(BaseModel):
    """Cost control settings."""
    budget_limit: Optional[float] = Field(None, description="Budget limit in USD")
    budget_period: str = Field("monthly", description="Budget period")
    alert_threshold: float = Field(0.8, description="Alert at % of budget")
    hard_limit: bool = Field(False, description="Stop at budget limit")
    cost_tracking_enabled: bool = Field(True)
    provider_costs: Dict[str, float] = Field(default_factory=dict)
    
    @validator('budget_period')
    def validate_period(cls, v):
        """Validate budget period."""
        valid_periods = ["daily", "weekly", "monthly", "yearly"]
        if v not in valid_periods:
            raise ValueError(f"Invalid period. Must be one of: {valid_periods}")
        return vclass ConfigurationSchema(BaseModel):
    """Complete configuration schema."""
    version: str = Field("2.0", description="Configuration version")
    profile: ConfigurationProfile = Field(ConfigurationProfile.DEVELOPMENT)
    providers: Dict[str, ProviderConfig] = Field(default_factory=dict)
    models: Dict[str, ModelSettings] = Field(default_factory=dict)
    cost_control: CostControl = Field(default_factory=CostControl)
    profiles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    features: Dict[str, bool] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    

class ConfigurationChange(BaseModel):
    """Audit log entry for configuration changes."""
    id: str
    timestamp: datetime
    change_type: ConfigChangeType
    user: Optional[str]
    path: str
    old_value: Optional[Any]
    new_value: Optional[Any]
    rollback_id: Optional[str]
    description: Optional[str]


class ConfigurationValidator:
    """Validates configuration changes before applying."""
    
    def __init__(self):
        self.validators: Dict[str, List[Callable]] = defaultdict(list)
        self._setup_default_validators()
    
    def _setup_default_validators(self):
        """Set up default validation rules."""
        self.add_validator("providers.*", self._validate_provider)
        self.add_validator("models.*", self._validate_model)
        self.add_validator("cost_control", self._validate_cost_control)
        
    def add_validator(self, path_pattern: str, validator_func: Callable):
        """Add a custom validator for a configuration path pattern."""
        self.validators[path_pattern].append(validator_func)
        
    def validate(self, path: str, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate a configuration value."""
        for pattern, validators in self.validators.items():
            if self._matches_pattern(path, pattern):
                for validator in validators:
                    try:
                        if not validator(value):
                            return False, f"Validation failed for {path}"
                    except Exception as e:
                        return False, str(e)
        return True, None
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern (supports wildcards)."""
        import fnmatch
        return fnmatch.fnmatch(path, pattern)
    
    def _validate_provider(self, config: Dict) -> bool:
        """Validate provider configuration."""
        try:
            ProviderConfig(**config)
            return True
        except Exception:
            return False
            
    def _validate_model(self, config: Dict) -> bool:
        """Validate model configuration."""
        try:
            ModelSettings(**config)
            return True
        except Exception:
            return False
            
    def _validate_cost_control(self, config: Dict) -> bool:
        """Validate cost control configuration."""
        try:
            CostControl(**config)
            return True
        except Exception:
            return Falseclass ConfigurationMigrator:
    """Handles configuration migrations between versions."""
    
    def __init__(self):
        self.migrations = {
            "1.0": self._migrate_v1_to_v2,
        }
        
    def migrate(self, config: Dict, from_version: str, to_version: str = "2.0") -> Dict:
        """Migrate configuration to target version."""
        current_version = from_version
        
        while current_version != to_version:
            if current_version in self.migrations:
                config = self.migrations[current_version](config)
                current_version = self._get_next_version(current_version)
            else:
                raise ValueError(f"No migration path from {current_version}")
                
        return config
        
    def _get_next_version(self, version: str) -> str:
        """Get next version in migration path."""
        version_map = {
            "1.0": "2.0",
        }
        return version_map.get(version, version)
        
    def _migrate_v1_to_v2(self, config: Dict) -> Dict:
        """Migrate from v1.0 to v2.0 configuration format."""
        new_config = {
            "version": "2.0",
            "profile": ConfigurationProfile.DEVELOPMENT.value,
            "providers": {},
            "models": {},
            "cost_control": {},
            "profiles": config.get("profiles", {}),
            "features": {},
            "metadata": config.get("metadata", {})
        }
        
        # Migrate old model configs
        if "configs" in config:
            for model_id, model_config in config["configs"].items():
                provider = LLMProvider(model_config.get("provider", "openai"))
                
                # Create provider config if not exists
                if provider.value not in new_config["providers"]:
                    new_config["providers"][provider.value] = {
                        "provider": provider.value,
                        "api_key": model_config.get("api_key"),
                        "api_base": model_config.get("api_base"),
                        "enabled": True
                    }
                
                # Create model settings
                new_config["models"][model_id] = {
                    "model_name": model_config.get("model_name", model_id),
                    "provider": provider.value,
                    "temperature": model_config.get("temperature", 0.7),
                    "max_tokens": model_config.get("max_tokens", 2048),
                    "context_length": model_config.get("context_length", 4096),
                    "tools_enabled": model_config.get("tools_enabled", True)
                }
                
        return new_configclass LLMConfigManager:
    """
    Dynamic LLM Configuration Manager with runtime updates, validation, and security.
    
    Features:
    - Runtime configuration updates without restart
    - Configuration validation and migration
    - Environment-specific profiles
    - Secure API key management
    - Audit logging and rollback
    - A/B testing support
    - Hot-reload capabilities
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize the LLM configuration manager."""
        # Configuration storage
        self.config_dir = config_dir or Path.home() / ".intellicrack" / "llm_configs"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.config_file = self.config_dir / "config.yaml"
        self.secrets_file = self.config_dir / "secrets.enc"
        self.audit_file = self.config_dir / "audit.jsonl"
        self.backup_dir = self.config_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        
        # Components
        self.validator = ConfigurationValidator()
        self.migrator = ConfigurationMigrator()
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # State
        self.config: ConfigurationSchema = self._load_config()
        self.audit_log: deque = deque(maxlen=1000)
        self.change_callbacks: List[Callable] = []
        self.ab_tests: Dict[str, Dict] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        self._config_version = 0
        self._hot_reload_enabled = True
        self._file_watcher_thread = None
        
        # Performance
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._cache_ttl = 300  # 5 minutes
        
        # Cost tracking
        self._usage_tracker = defaultdict(lambda: {"tokens": 0, "cost": 0.0})
        self._last_reset = datetime.now()
        
        # Start file watcher for hot reload
        if self._hot_reload_enabled:
            self._start_file_watcher()
            
        # Auto-load models
        self._auto_load_models()    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for API keys."""
        key_file = self.config_dir / ".key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions on key file
            if os.name != 'nt':  # Unix-like systems
                os.chmod(key_file, 0o600)
            return key
            
    def _encrypt_value(self, value: str) -> str:
        """Encrypt a sensitive value."""
        if not value or value.startswith("enc:"):
            return value
        encrypted = self.cipher.encrypt(value.encode())
        return f"enc:{encrypted.decode()}"
        
    def _decrypt_value(self, value: str) -> str:
        """Decrypt a sensitive value."""
        if not value or not value.startswith("enc:"):
            return value
        encrypted = value[4:]  # Remove "enc:" prefix
        try:
            decrypted = self.cipher.decrypt(encrypted.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt value: {e}")
            return ""    def _load_config(self) -> ConfigurationSchema:
        """Load configuration from file."""
        if not self.config_file.exists():
            return self._create_default_config()
            
        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            # Migrate if needed
            version = data.get("version", "1.0")
            if version != "2.0":
                data = self.migrator.migrate(data, version)
                
            # Decrypt API keys
            if "providers" in data:
                for provider_id, provider_config in data["providers"].items():
                    if "api_key" in provider_config:
                        provider_config["api_key"] = self._decrypt_value(provider_config["api_key"])
                        
            return ConfigurationSchema(**data)
            
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._create_default_config()
            
    def _save_config(self):
        """Save configuration to file."""
        with self._lock:
            # Create backup
            self._create_backup()
            
            # Prepare data for saving
            data = self.config.dict()
            
            # Encrypt API keys
            if "providers" in data:
                for provider_id, provider_config in data["providers"].items():
                    if "api_key" in provider_config and provider_config["api_key"]:
                        provider_config["api_key"] = self._encrypt_value(provider_config["api_key"])
            
            # Save to file
            with open(self.config_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
                
            self._config_version += 1    def _create_default_config(self) -> ConfigurationSchema:
        """Create default configuration."""
        return ConfigurationSchema(
            profile=ConfigurationProfile.DEVELOPMENT,
            providers={
                "openai": ProviderConfig(
                    provider=LLMProvider.OPENAI,
                    rate_limit=60,
                    timeout=30,
                    enabled=True
                ),
                "anthropic": ProviderConfig(
                    provider=LLMProvider.ANTHROPIC,
                    rate_limit=50,
                    timeout=30,
                    enabled=True
                ),
                "local": ProviderConfig(
                    provider=LLMProvider.LOCAL,
                    enabled=True
                )
            },
            profiles=self._get_default_profiles(),
            features={
                "hot_reload": True,
                "cost_tracking": True,
                "ab_testing": False,
                "auto_fallback": True,
                "caching": True
            }
        )
        
    def _get_default_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Get default configuration profiles."""
        return {
            "code_generation": {
                "name": "Code Generation",
                "description": "Optimized for generating code and scripts",
                "settings": {
                    "temperature": 0.2,
                    "max_tokens": 4096,
                    "top_p": 0.95,
                    "frequency_penalty": 0.0,
                    "presence_penalty": 0.0
                }
            },
            "analysis": {
                "name": "Binary Analysis",
                "description": "Optimized for analyzing binaries",
                "settings": {
                    "temperature": 0.1,
                    "max_tokens": 2048,
                    "top_p": 0.9
                }
            },
            "creative": {
                "name": "Creative Tasks",
                "description": "For brainstorming and creative solutions",
                "settings": {
                    "temperature": 0.8,
                    "max_tokens": 2048,
                    "top_p": 0.95,
                    "frequency_penalty": 0.3,
                    "presence_penalty": 0.3
                }
            }
        }    def get_provider_config(self, provider: Union[str, LLMProvider]) -> Optional[ProviderConfig]:
        """Get configuration for a specific provider."""
        if isinstance(provider, LLMProvider):
            provider = provider.value
            
        with self._lock:
            return self.config.providers.get(provider)
            
    def set_provider_config(self, provider: Union[str, LLMProvider], config: ProviderConfig):
        """Set configuration for a specific provider."""
        if isinstance(provider, LLMProvider):
            provider = provider.value
            
        with self._lock:
            old_value = self.config.providers.get(provider)
            self.config.providers[provider] = config
            self._save_config()
            
            # Log change
            self._log_change(
                ConfigChangeType.UPDATE if old_value else ConfigChangeType.CREATE,
                f"providers.{provider}",
                old_value.dict() if old_value else None,
                config.dict()
            )
            
            # Notify callbacks
            self._notify_change(f"providers.{provider}", old_value, config)
            
            # Update LLM manager
            self._update_llm_manager()    def get_model_settings(self, model_id: str) -> Optional[ModelSettings]:
        """Get settings for a specific model."""
        with self._lock:
            # Check cache first
            if model_id in self._cache:
                value, timestamp = self._cache[model_id]
                if time.time() - timestamp < self._cache_ttl:
                    return value
                    
            settings = self.config.models.get(model_id)
            if settings:
                self._cache[model_id] = (settings, time.time())
            return settings
            
    def set_model_settings(self, model_id: str, settings: ModelSettings):
        """Set settings for a specific model."""
        with self._lock:
            old_value = self.config.models.get(model_id)
            
            # Validate settings
            is_valid, error = self.validator.validate(f"models.{model_id}", settings.dict())
            if not is_valid:
                raise ValueError(f"Invalid model settings: {error}")
                
            self.config.models[model_id] = settings
            self._save_config()
            
            # Clear cache
            self._cache.pop(model_id, None)
            
            # Log change
            self._log_change(
                ConfigChangeType.UPDATE if old_value else ConfigChangeType.CREATE,
                f"models.{model_id}",
                old_value.dict() if old_value else None,
                settings.dict()
            )
            
            # Notify callbacks
            self._notify_change(f"models.{model_id}", old_value, settings)    def apply_profile(self, model_id: str, profile_name: str):
        """Apply a configuration profile to a model."""
        with self._lock:
            profile = self.config.profiles.get(profile_name)
            if not profile:
                raise ValueError(f"Profile not found: {profile_name}")
                
            model_settings = self.config.models.get(model_id)
            if not model_settings:
                raise ValueError(f"Model not found: {model_id}")
                
            # Apply profile settings
            settings = profile.get("settings", {})
            for key, value in settings.items():
                if hasattr(model_settings, key):
                    setattr(model_settings, key, value)
                    
            self.set_model_settings(model_id, model_settings)
            
    def set_environment(self, profile: ConfigurationProfile):
        """Switch to a different environment profile."""
        with self._lock:
            old_profile = self.config.profile
            self.config.profile = profile
            self._save_config()
            
            # Log change
            self._log_change(
                ConfigChangeType.UPDATE,
                "profile",
                old_profile.value,
                profile.value
            )
            
            # Reload configuration for new environment
            self._load_environment_config(profile)    def get_cost_control(self) -> CostControl:
        """Get cost control settings."""
        with self._lock:
            return self.config.cost_control
            
    def update_cost_control(self, updates: Dict[str, Any]):
        """Update cost control settings."""
        with self._lock:
            old_value = self.config.cost_control.dict()
            
            # Update fields
            for key, value in updates.items():
                if hasattr(self.config.cost_control, key):
                    setattr(self.config.cost_control, key, value)
                    
            self._save_config()
            
            # Log change
            self._log_change(
                ConfigChangeType.UPDATE,
                "cost_control",
                old_value,
                self.config.cost_control.dict()
            )
            
    def track_usage(self, model_id: str, tokens: int, cost: float):
        """Track model usage for cost control."""
        with self._lock:
            self._usage_tracker[model_id]["tokens"] += tokens
            self._usage_tracker[model_id]["cost"] += cost
            
            # Check budget limits
            if self.config.cost_control.budget_limit:
                total_cost = sum(u["cost"] for u in self._usage_tracker.values())
                
                # Check if we need to reset (based on period)
                if self._should_reset_usage():
                    self._reset_usage()
                    total_cost = cost
                    
                # Check alert threshold
                if total_cost >= self.config.cost_control.budget_limit * self.config.cost_control.alert_threshold:
                    logger.warning(f"Cost alert: ${total_cost:.2f} of ${self.config.cost_control.budget_limit:.2f} budget used")
                    
                # Check hard limit
                if self.config.cost_control.hard_limit and total_cost >= self.config.cost_control.budget_limit:
                    raise RuntimeError(f"Budget limit exceeded: ${total_cost:.2f}")
                    
    def _should_reset_usage(self) -> bool:
        """Check if usage tracking should be reset based on period."""
        now = datetime.now()
        period = self.config.cost_control.budget_period
        
        if period == "daily":
            return now.date() != self._last_reset.date()
        elif period == "weekly":
            return now.isocalendar()[1] != self._last_reset.isocalendar()[1]
        elif period == "monthly":
            return now.month != self._last_reset.month or now.year != self._last_reset.year
        elif period == "yearly":
            return now.year != self._last_reset.year
            
        return False
        
    def _reset_usage(self):
        """Reset usage tracking."""
        self._usage_tracker.clear()
        self._last_reset = datetime.now()    def create_ab_test(self, test_name: str, variants: Dict[str, Dict[str, Any]], 
                       allocation: Optional[Dict[str, float]] = None):
        """Create an A/B test for configuration variants."""
        with self._lock:
            if not self.config.features.get("ab_testing", False):
                raise RuntimeError("A/B testing is not enabled")
                
            if test_name in self.ab_tests:
                raise ValueError(f"A/B test already exists: {test_name}")
                
            # Default equal allocation
            if not allocation:
                num_variants = len(variants)
                allocation = {k: 1.0 / num_variants for k in variants}
                
            # Validate allocation sums to 1.0
            if abs(sum(allocation.values()) - 1.0) > 0.001:
                raise ValueError("Allocation percentages must sum to 1.0")
                
            self.ab_tests[test_name] = {
                "variants": variants,
                "allocation": allocation,
                "active": True,
                "results": defaultdict(lambda: {"count": 0, "success": 0})
            }
            
    def get_ab_variant(self, test_name: str, user_id: str) -> Tuple[str, Dict[str, Any]]:
        """Get A/B test variant for a user."""
        with self._lock:
            if test_name not in self.ab_tests:
                raise ValueError(f"A/B test not found: {test_name}")
                
            test = self.ab_tests[test_name]
            if not test["active"]:
                raise ValueError(f"A/B test is not active: {test_name}")
                
            # Deterministic assignment based on user_id
            hash_value = int(hashlib.md5(f"{test_name}:{user_id}".encode()).hexdigest(), 16)
            assignment = (hash_value % 100) / 100.0
            
            # Select variant based on allocation
            cumulative = 0.0
            for variant_name, percentage in test["allocation"].items():
                cumulative += percentage
                if assignment < cumulative:
                    return variant_name, test["variants"][variant_name]
                    
            # Fallback to last variant
            return list(test["variants"].items())[-1]    def register_change_callback(self, callback: Callable[[str, Any, Any], None]):
        """Register a callback for configuration changes."""
        with self._lock:
            self.change_callbacks.append(callback)
            
    def _notify_change(self, path: str, old_value: Any, new_value: Any):
        """Notify all registered callbacks of a configuration change."""
        for callback in self.change_callbacks:
            try:
                callback(path, old_value, new_value)
            except Exception as e:
                logger.error(f"Error in change callback: {e}")
                
    def _log_change(self, change_type: ConfigChangeType, path: str, 
                    old_value: Any, new_value: Any):
        """Log a configuration change to audit log."""
        change = ConfigurationChange(
            id=hashlib.sha256(f"{time.time()}:{path}".encode()).hexdigest()[:16],
            timestamp=datetime.now(),
            change_type=change_type,
            user=os.environ.get("USER", "system"),
            path=path,
            old_value=old_value,
            new_value=new_value,
            rollback_id=None,
            description=None
        )
        
        self.audit_log.append(change)
        
        # Write to audit file
        try:
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(change.dict(), default=str) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")    def rollback_change(self, change_id: str):
        """Rollback a specific configuration change."""
        with self._lock:
            # Find change in audit log
            change = None
            for entry in reversed(self.audit_log):
                if entry.id == change_id:
                    change = entry
                    break
                    
            if not change:
                raise ValueError(f"Change not found: {change_id}")
                
            if change.change_type == ConfigChangeType.ROLLBACK:
                raise ValueError("Cannot rollback a rollback")
                
            # Apply rollback
            path_parts = change.path.split(".")
            if len(path_parts) == 2:
                category, key = path_parts
                
                if category == "providers" and change.old_value:
                    self.config.providers[key] = ProviderConfig(**change.old_value)
                elif category == "models" and change.old_value:
                    self.config.models[key] = ModelSettings(**change.old_value)
                elif category == "cost_control":
                    self.config.cost_control = CostControl(**change.old_value)
                    
            self._save_config()
            
            # Log rollback
            self._log_change(
                ConfigChangeType.ROLLBACK,
                change.path,
                change.new_value,
                change.old_value
            )    def _create_backup(self):
        """Create a backup of current configuration."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"config_backup_{timestamp}.yaml"
        
        # Keep only last 10 backups
        backups = sorted(self.backup_dir.glob("config_backup_*.yaml"))
        if len(backups) >= 10:
            for old_backup in backups[:-9]:
                old_backup.unlink()
                
        # Copy current config
        if self.config_file.exists():
            shutil.copy2(self.config_file, backup_file)
            
    def restore_backup(self, backup_timestamp: str):
        """Restore configuration from a backup."""
        with self._lock:
            backup_file = self.backup_dir / f"config_backup_{backup_timestamp}.yaml"
            
            if not backup_file.exists():
                raise ValueError(f"Backup not found: {backup_timestamp}")
                
            # Load backup
            shutil.copy2(backup_file, self.config_file)
            self.config = self._load_config()
            
            # Log restore
            self._log_change(
                ConfigChangeType.ROLLBACK,
                "full_config",
                None,
                {"restored_from": backup_timestamp}
            )
            
            # Notify all callbacks
            self._notify_change("full_config", None, self.config)    def _start_file_watcher(self):
        """Start file watcher for hot reload."""
        def watch_config():
            last_mtime = 0
            while self._hot_reload_enabled:
                try:
                    if self.config_file.exists():
                        current_mtime = self.config_file.stat().st_mtime
                        if current_mtime > last_mtime and last_mtime > 0:
                            logger.info("Configuration file changed, reloading...")
                            with self._lock:
                                self.config = self._load_config()
                                self._notify_change("full_config", None, self.config)
                                self._update_llm_manager()
                        last_mtime = current_mtime
                except Exception as e:
                    logger.error(f"Error in file watcher: {e}")
                    
                time.sleep(1)
                
        self._file_watcher_thread = threading.Thread(
            target=watch_config,
            daemon=True,
            name="ConfigFileWatcher"
        )
        self._file_watcher_thread.start()
        
    def enable_hot_reload(self, enabled: bool = True):
        """Enable or disable hot reload."""
        with self._lock:
            self._hot_reload_enabled = enabled
            self.config.features["hot_reload"] = enabled
            
            if enabled and not self._file_watcher_thread:
                self._start_file_watcher()    def _load_environment_config(self, profile: ConfigurationProfile):
        """Load environment-specific configuration."""
        env_file = self.config_dir / f"config.{profile.value}.yaml"
        
        if env_file.exists():
            try:
                with open(env_file, 'r') as f:
                    env_data = yaml.safe_load(f) or {}
                    
                # Merge with base config
                for key, value in env_data.items():
                    if hasattr(self.config, key):
                        if isinstance(value, dict):
                            getattr(self.config, key).update(value)
                        else:
                            setattr(self.config, key, value)
                            
            except Exception as e:
                logger.error(f"Failed to load environment config: {e}")
                
    def _update_llm_manager(self):
        """Update LLM manager with current configuration."""
        try:
            llm_manager = get_llm_manager()
            
            # Update provider configurations
            for provider_id, provider_config in self.config.providers.items():
                if not provider_config.enabled:
                    continue
                    
                # Update existing models with new provider settings
                for model_id, model_settings in self.config.models.items():
                    if model_settings.provider.value == provider_id:
                        config = LLMConfig(
                            provider=model_settings.provider,
                            model_name=model_settings.model_name,
                            api_key=provider_config.api_key,
                            api_base=provider_config.api_base,
                            context_length=model_settings.context_length,
                            temperature=model_settings.temperature,
                            max_tokens=model_settings.max_tokens,
                            tools_enabled=model_settings.tools_enabled,
                            custom_params={
                                "top_p": model_settings.top_p,
                                "frequency_penalty": model_settings.frequency_penalty,
                                "presence_penalty": model_settings.presence_penalty,
                                "cache_enabled": model_settings.cache_enabled,
                                "cache_ttl": model_settings.cache_ttl
                            }
                        )
                        
                        llm_manager.register_llm(model_id, config)
                        
        except Exception as e:
            logger.error(f"Failed to update LLM manager: {e}")    def _auto_load_models(self):
        """Auto-load models based on configuration."""
        try:
            llm_manager = get_llm_manager()
            loaded = 0
            failed = 0
            
            for model_id, model_settings in self.config.models.items():
                provider_config = self.config.providers.get(model_settings.provider.value)
                
                if not provider_config or not provider_config.enabled:
                    continue
                    
                try:
                    config = LLMConfig(
                        provider=model_settings.provider,
                        model_name=model_settings.model_name,
                        api_key=provider_config.api_key,
                        api_base=provider_config.api_base,
                        context_length=model_settings.context_length,
                        temperature=model_settings.temperature,
                        max_tokens=model_settings.max_tokens,
                        tools_enabled=model_settings.tools_enabled,
                        custom_params={
                            "top_p": model_settings.top_p,
                            "frequency_penalty": model_settings.frequency_penalty,
                            "presence_penalty": model_settings.presence_penalty
                        }
                    )
                    
                    if llm_manager.register_llm(model_id, config):
                        loaded += 1
                        logger.info(f"Auto-loaded model: {model_id}")
                    else:
                        failed += 1
                        logger.warning(f"Failed to register model: {model_id}")
                        
                except Exception as e:
                    failed += 1
                    logger.error(f"Error loading model {model_id}: {e}")
                    
            logger.info(f"Auto-load complete: {loaded} loaded, {failed} failed")
            
        except Exception as e:
            logger.error(f"Failed to auto-load models: {e}")    def export_config(self, export_path: Path, include_secrets: bool = False,
                      format: str = "yaml"):
        """Export configuration to file."""
        with self._lock:
            export_data = self.config.dict()
            
            # Remove sensitive data if requested
            if not include_secrets:
                if "providers" in export_data:
                    for provider_config in export_data["providers"].values():
                        if "api_key" in provider_config:
                            provider_config["api_key"] = "***REDACTED***"
                            
            # Add metadata
            export_data["_metadata"] = {
                "exported_at": datetime.now().isoformat(),
                "version": self.config.version,
                "profile": self.config.profile.value
            }
            
            # Save in requested format
            if format == "yaml":
                with open(export_path, 'w') as f:
                    yaml.dump(export_data, f, default_flow_style=False)
            elif format == "json":
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
            # Log export
            self._log_change(
                ConfigChangeType.EXPORT,
                "full_config",
                None,
                {"export_path": str(export_path), "include_secrets": include_secrets}
            )    def import_config(self, import_path: Path, merge: bool = True,
                      validate: bool = True):
        """Import configuration from file."""
        with self._lock:
            # Load import data
            if import_path.suffix in [".yaml", ".yml"]:
                with open(import_path, 'r') as f:
                    import_data = yaml.safe_load(f)
            elif import_path.suffix == ".json":
                with open(import_path, 'r') as f:
                    import_data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {import_path.suffix}")
                
            # Remove metadata
            import_data.pop("_metadata", None)
            
            # Validate if requested
            if validate:
                try:
                    ConfigurationSchema(**import_data)
                except Exception as e:
                    raise ValueError(f"Invalid configuration: {e}")
                    
            # Merge or replace
            if merge:
                # Deep merge with existing config
                for key, value in import_data.items():
                    if hasattr(self.config, key):
                        if isinstance(value, dict):
                            existing = getattr(self.config, key)
                            if isinstance(existing, dict):
                                existing.update(value)
                            else:
                                setattr(self.config, key, value)
                        else:
                            setattr(self.config, key, value)
            else:
                # Replace entire config
                self.config = ConfigurationSchema(**import_data)
                
            self._save_config()
            
            # Log import
            self._log_change(
                ConfigChangeType.IMPORT,
                "full_config",
                None,
                {"import_path": str(import_path), "merge": merge}
            )
            
            # Update LLM manager
            self._update_llm_manager()    def get_audit_log(self, limit: int = 100) -> List[ConfigurationChange]:
        """Get recent audit log entries."""
        with self._lock:
            entries = list(self.audit_log)
            
            # Also load from file if needed
            if len(entries) < limit and self.audit_file.exists():
                try:
                    with open(self.audit_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                entry_data = json.loads(line)
                                entries.append(ConfigurationChange(**entry_data))
                                if len(entries) >= limit:
                                    break
                except Exception as e:
                    logger.error(f"Failed to read audit log: {e}")
                    
            return entries[-limit:]
            
    def validate_config(self) -> Tuple[bool, List[str]]:
        """Validate entire configuration."""
        errors = []
        
        try:
            # Validate schema
            ConfigurationSchema(**self.config.dict())
        except Exception as e:
            errors.append(f"Schema validation failed: {e}")
            
        # Validate providers
        for provider_id, provider_config in self.config.providers.items():
            is_valid, error = self.validator.validate(f"providers.{provider_id}", provider_config.dict())
            if not is_valid:
                errors.append(f"Provider {provider_id}: {error}")
                
        # Validate models
        for model_id, model_settings in self.config.models.items():
            is_valid, error = self.validator.validate(f"models.{model_id}", model_settings.dict())
            if not is_valid:
                errors.append(f"Model {model_id}: {error}")
                
        # Validate cost control
        is_valid, error = self.validator.validate("cost_control", self.config.cost_control.dict())
        if not is_valid:
            errors.append(f"Cost control: {error}")
            
        return len(errors) == 0, errors    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics for all models."""
        with self._lock:
            stats = {
                "total_tokens": sum(u["tokens"] for u in self._usage_tracker.values()),
                "total_cost": sum(u["cost"] for u in self._usage_tracker.values()),
                "by_model": dict(self._usage_tracker),
                "period_start": self._last_reset.isoformat(),
                "budget_remaining": None
            }
            
            if self.config.cost_control.budget_limit:
                stats["budget_remaining"] = max(0, 
                    self.config.cost_control.budget_limit - stats["total_cost"])
                    
            return stats
            
    def clear_cache(self):
        """Clear configuration cache."""
        with self._lock:
            self._cache.clear()
            
    def get_recommended_models(self, use_case: str) -> List[str]:
        """Get recommended models for a specific use case."""
        profile = self.config.profiles.get(use_case, {})
        recommended = profile.get("recommended_models", [])
        
        # Filter to only available models
        available = []
        for model_name in recommended:
            for model_id, settings in self.config.models.items():
                if settings.model_name == model_name:
                    provider_config = self.config.providers.get(settings.provider.value)
                    if provider_config and provider_config.enabled:
                        available.append(model_id)
                        break
                        
        return available


# Global instance
_CONFIG_MANAGER = None


def get_llm_config_manager() -> LLMConfigManager:
    """Get the global LLM configuration manager."""
    global _CONFIG_MANAGER
    if _CONFIG_MANAGER is None:
        _CONFIG_MANAGER = LLMConfigManager()
    return _CONFIG_MANAGER
# Additional helper functions for UI integration
def create_provider_from_ui(provider_name: str, api_key: str, 
                          api_base: Optional[str] = None) -> ProviderConfig:
    """Create a provider configuration from UI inputs."""
    provider = LLMProvider(provider_name.lower())
    
    return ProviderConfig(
        provider=provider,
        api_key=api_key,
        api_base=api_base,
        enabled=True
    )


def create_model_from_ui(model_name: str, provider_name: str,
                        temperature: float = 0.7,
                        max_tokens: int = 2048) -> ModelSettings:
    """Create model settings from UI inputs."""
    provider = LLMProvider(provider_name.lower())
    
    return ModelSettings(
        model_name=model_name,
        provider=provider,
        temperature=temperature,
        max_tokens=max_tokens
    )


async def test_provider_connection(provider_config: ProviderConfig) -> Tuple[bool, str]:
    """Test if a provider configuration is valid and accessible."""
    try:
        llm_manager = get_llm_manager()
        
        # Create temporary model config
        test_config = LLMConfig(
            provider=provider_config.provider,
            model_name="test",
            api_key=provider_config.api_key,
            api_base=provider_config.api_base
        )
        
        # Try to create backend
        test_id = f"test_{provider_config.provider.value}_{time.time()}"
        if llm_manager.register_llm(test_id, test_config):
            # Test with simple prompt
            response = await llm_manager.generate_async(
                test_id,
                "Hello",
                max_tokens=10
            )
            
            # Clean up
            llm_manager.unregister_llm(test_id)
            
            if response:
                return True, "Connection successful"
            else:
                return False, "No response from model"
        else:
            return False, "Failed to register model"
            
    except Exception as e:
        return False, str(e)