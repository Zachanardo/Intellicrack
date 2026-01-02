"""Centralized Secrets Management for Intellicrack.

This module provides secure storage and retrieval of sensitive information
such as API keys, tokens, and passwords.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
from pathlib import Path
from typing import Any, cast

from intellicrack.core.config_manager import IntellicrackConfig

from .logger import get_logger


logger = get_logger(__name__)

IMPORT_ERROR_MSG = "Import error in secrets_manager: %s"
CONFIG_DIR_KEY = "secrets.config_directory"
ENCRYPTION_ENABLED_KEY = "secrets.encryption_enabled"
KEYRING_IN_USE_KEY = "secrets.keyring_in_use"

Fernet: Any = None
PBKDF2HMAC: Any = None
hashes: Any = None
HAS_CRYPTOGRAPHY: bool = False
try:
    from intellicrack.handlers.cryptography_handler import (
        PBKDF2HMAC as _PBKDF2HMAC,
        Fernet as _Fernet,
        hashes as _hashes,
    )

    Fernet = _Fernet
    PBKDF2HMAC = _PBKDF2HMAC
    hashes = _hashes
    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)

keyring_module: Any = None
HAS_KEYRING: bool = False
try:
    import keyring as _keyring_module

    keyring_module = _keyring_module
    HAS_KEYRING = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)

load_dotenv: Any = None
find_dotenv: Any = None
HAS_DOTENV: bool = False
try:
    from dotenv import (
        find_dotenv as _find_dotenv,
        load_dotenv as _load_dotenv,
    )

    load_dotenv = _load_dotenv
    find_dotenv = _find_dotenv
    HAS_DOTENV = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)


class SecretsManager:
    """Centralized secrets management with multiple backend support.

    Features:
    - Environment variable loading (.env files)
    - Encrypted file storage
    - OS keychain integration (Windows Credential Manager, macOS Keychain, Linux Secret Service)
    - Fallback mechanisms
    - Key rotation support
    """

    # Service name for keyring
    SERVICE_NAME = "Intellicrack"

    # Known secret keys
    KNOWN_SECRETS = [
        # LLM API Keys
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "COHERE_API_KEY",
        "HUGGINGFACE_API_TOKEN",
        "GROQ_API_KEY",
        "TOGETHER_API_KEY",
        "OPENROUTER_API_KEY",
        # Cloud Services
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_API_KEY",
        "GCP_API_KEY",
        # Database
        "DATABASE_URL",
        "DB_PASSWORD",
        # Application Secrets
        "JWT_SECRET_KEY",
        "ENCRYPTION_KEY",
        "SESSION_SECRET",
        # Custom/Generic
        "API_KEY",
        "SECRET_KEY",
        "PRIVATE_KEY",
    ]

    def __init__(self, config_dir: Path | None = None) -> None:
        """Initialize the secrets manager.

        Args:
            config_dir: Optional configuration directory path. If None, uses default.

        Raises:
            OSError: If unable to create config directory.
            Exception: If environment file loading fails or encryption initialization fails.
        """
        self._central_config: IntellicrackConfig | None = None
        self._config_dir_override = config_dir
        self._cipher: Any = None  # Will be Fernet or None

        # Get config directory from central config or use provided/default
        if config_dir is None:
            config_dir_str_obj = self.central_config.get(CONFIG_DIR_KEY)
            if not config_dir_str_obj:
                config_dir = self._get_default_config_dir()
                config_dir_str = str(config_dir)
                # Store the default in central config
                self.central_config.set(CONFIG_DIR_KEY, config_dir_str)
            else:
                # Type narrowing: convert object to str
                config_dir_str = str(config_dir_str_obj)
            self.config_dir = Path(config_dir_str)
        else:
            self.config_dir = Path(config_dir)
            # Update central config with the provided path
            self.central_config.set(CONFIG_DIR_KEY, str(self.config_dir))

        self.secrets_file = self.config_dir / "secrets.enc"
        self.key_file = self.config_dir / ".key"

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Load environment variables
        self._load_env_files()

        # Initialize encryption
        self._init_encryption()

        # Cache for loaded secrets
        self._cache: dict[str, Any] = {}
        self._load_secrets()

        # Sync encrypted keys metadata to central config
        self._sync_metadata_to_central_config()

    def _get_central_config(self) -> IntellicrackConfig:
        """Lazy load central config.

        Returns:
            The central Intellicrack configuration instance.

        Raises:
            Exception: If retrieving the global configuration instance fails (exception
                is raised to caller).
        """
        if self._central_config is None:
            from intellicrack.core.config_manager import get_config

            self._central_config = get_config()
        return self._central_config

    @property
    def central_config(self) -> IntellicrackConfig:
        """Get central config instance (lazy-loaded).

        Returns:
            The central Intellicrack configuration instance.

        Raises:
            Exception: If retrieving the global configuration instance fails (exception
                is raised to caller).
        """
        return self._get_central_config()

    def _get_default_config_dir(self) -> Path:
        r"""Get unified configuration directory.

        Uses relative path to Intellicrack root for all platforms to ensure consistency.

        Returns:
            Path to the default secrets configuration directory.

        Raises:
            Exception: If determining the Intellicrack root path fails (exception is
                raised to caller).
        """
        import intellicrack

        root = Path(intellicrack.__file__).parent.parent
        return root / "config" / "secrets"

    def _load_env_files(self) -> None:
        """Load environment variables from .env files.

        Loads from unified config directory first, then searches project directories
        for .env files with fallback locations.

        Raises:
            OSError: If reading .env files fails (though errors are logged and not raised).
        """
        if not HAS_DOTENV or load_dotenv is None:
            logger.warning("python-dotenv not available - .env files will not be loaded")
            return

        # Priority 1: Check unified config directory first
        import intellicrack

        root = Path(intellicrack.__file__).parent.parent
        unified_config_dir = root / "config"
        unified_env_file = unified_config_dir / ".env"
        if unified_env_file.exists():
            load_dotenv(unified_env_file, override=True)
            logger.debug("Loaded environment from unified config: %s", unified_env_file)
            return  # Use only the unified config if it exists

        # Fallback: Look for .env files in other locations
        env_files = [
            ".env.local",  # Highest priority - user's local overrides
            ".env.production",  # Production settings
            ".env",  # Default settings
            ".env.example",  # Fallback example (should not contain real secrets)
        ]

        # Find project root (where .env files typically are)
        current = Path.cwd()
        while current != current.parent:
            for env_file in env_files:
                env_path = current / env_file
                if env_path.exists():
                    load_dotenv(env_path, override=True)
                    logger.debug("Loaded environment from %s", env_path)

            # Check if we're at project root (has intellicrack directory)
            if (current / "intellicrack").exists():
                break
            current = current.parent

    def _set_encryption_status(self, enabled: bool, uses_keyring: bool) -> None:
        """Set encryption status in central config.

        Args:
            enabled: Whether encryption is enabled.
            uses_keyring: Whether the keyring backend is being used.

        Raises:
            Exception: If setting configuration values fails (though errors are logged).
        """
        self.central_config.set(ENCRYPTION_ENABLED_KEY, enabled)
        self.central_config.set(KEYRING_IN_USE_KEY, uses_keyring)

    def _load_encryption_key(self) -> None:
        """Load encryption key from keychain or file.

        Attempts to load from OS keychain first, then falls back to file storage.

        Raises:
            Exception: If decryption initialization fails (exception is caught and
                logged; cipher is set to generated key as fallback).
        """
        if not HAS_CRYPTOGRAPHY or Fernet is None:
            self._cipher = None
            return

        keyring_backend = self.central_config.get("secrets.keyring_backend", "auto")
        try:
            if HAS_KEYRING and keyring_module is not None and keyring_backend != "disabled":
                if key_str := keyring_module.get_password(self.SERVICE_NAME, "encryption_key"):
                    self._cipher = Fernet(key_str.encode())
                    self._set_encryption_status(True, True)
                    return

            if self.key_file.exists():
                key = self.key_file.read_bytes()
                self._cipher = Fernet(key)
            else:
                self._cipher = Fernet(Fernet.generate_key())
            self._set_encryption_status(True, False)
        except Exception as e:
            logger.exception("Failed to initialize encryption: %s", e, exc_info=True)
            self._cipher = Fernet(Fernet.generate_key())
            self._set_encryption_status(True, False)

    def _disable_encryption(self) -> None:
        """Disable encryption and set status.

        Clears the cipher and updates configuration to reflect disabled encryption.

        Raises:
            Exception: If setting configuration values fails (though errors are logged).
        """
        self._set_encryption_status(False, False)
        self._cipher = None

    def _init_encryption(self) -> None:
        """Initialize encryption for file-based secret storage.

        Generates encryption keys and configures encryption based on available
        libraries and configuration settings. Attempts keyring storage first,
        then falls back to file-based key storage.

        Raises:
            Exception: If keyring storage fails (exception is caught; falls back to
                file storage) or if configuration updates fail (logged as warning).
        """
        # Get encryption settings from central config
        use_encryption = self.central_config.get("secrets.use_encryption", True)
        keyring_backend = self.central_config.get("secrets.keyring_backend", "auto")

        if not HAS_CRYPTOGRAPHY or Fernet is None:
            logger.warning("Cryptography not available - secrets will be stored as plain text")
            self._disable_encryption()
            return

        if not use_encryption:
            logger.info("Encryption disabled by configuration")
            self._disable_encryption()
            return

        if not self.key_file.exists():
            # Generate a new encryption key
            key = Fernet.generate_key()
            # Try to store in OS keychain first based on backend config
            if HAS_KEYRING and keyring_module is not None and keyring_backend != "disabled":
                try:
                    keyring_module.set_password(self.SERVICE_NAME, "encryption_key", key.decode())
                    # Also save to file as backup
                    self._write_key_file(key)
                    self.central_config.set(KEYRING_IN_USE_KEY, True)
                except Exception as e:
                    logger.warning("Failed to store key in keychain: %s", e, exc_info=True)
                    # Fall back to file storage
                    self._write_key_file(key)
                    self.central_config.set(KEYRING_IN_USE_KEY, False)
            else:
                # No keyring, just use file
                self._write_key_file(key)
                self.central_config.set(KEYRING_IN_USE_KEY, False)

        # Load the encryption key
        self._load_encryption_key()

    def _write_key_file(self, key: bytes) -> None:
        """Write encryption key to file with restricted permissions.

        Args:
            key: The encryption key bytes to write to file.

        Raises:
            OSError: If writing to or changing permissions on the key file fails.
        """
        self.key_file.write_bytes(key)
        self.key_file.chmod(0o600)

    def _load_secrets(self) -> None:
        """Load secrets from encrypted file.

        Decrypts the secrets file if encryption is enabled, or loads as plain text.
        Errors during loading result in an empty cache.

        Raises:
            Exception: If decryption or JSON parsing fails (exception is caught; empty
                cache is used as fallback).
        """
        if not self.secrets_file.exists():
            self._cache = {}
            return

        try:
            if self._cipher is None:
                # No encryption available, load as plain text
                data = self.secrets_file.read_text()
                self._cache = json.loads(data)
            else:
                # Decrypt data
                encrypted_data = self.secrets_file.read_bytes()
                decrypted_data = self._cipher.decrypt(encrypted_data)
                self._cache = json.loads(decrypted_data.decode())
            logger.debug("Loaded secrets from file")
        except Exception as e:
            logger.exception("Failed to load secrets file: %s", e, exc_info=True)
            self._cache = {}

    def _save_secrets(self) -> None:
        """Save secrets to encrypted file.

        Encrypts secrets before writing if encryption is enabled, otherwise saves
        as plain text with a warning. Sets restricted file permissions.

        Raises:
            OSError: If writing to or changing permissions on the secrets file fails
                (exception is caught and logged).
            Exception: If encryption or JSON serialization fails (exception is caught
                and logged).
        """
        try:
            if self._cipher is None:
                # No encryption available, save as plain text (with warning)
                logger.warning("Saving secrets as plain text - install cryptography for encryption")
                data = json.dumps(self._cache, indent=2)
                self.secrets_file.write_text(data)
                self.secrets_file.chmod(0o600)  # Restrict permissions
            else:
                # Encrypt data
                data_bytes = json.dumps(self._cache).encode()
                encrypted_data = self._cipher.encrypt(data_bytes)
                self.secrets_file.write_bytes(encrypted_data)
                self.secrets_file.chmod(0o600)  # Restrict permissions

            logger.debug("Saved secrets to file")
        except Exception as e:
            logger.exception("Failed to save secrets: %s", e, exc_info=True)

    def _get_from_keyring(self, key: str) -> str | None:
        """Get secret from OS keychain with error handling.

        Args:
            key: The secret key to retrieve from keychain.

        Returns:
            The secret value if found, None otherwise.

        Raises:
            Exception: If keychain lookup fails (exception is caught; None is returned).
        """
        if not HAS_KEYRING or keyring_module is None:
            return None
        try:
            result = keyring_module.get_password(self.SERVICE_NAME, key)
            return cast("str | None", result)
        except Exception as e:
            logger.debug("Keychain lookup failed for %s: %s", key, e, exc_info=True)
            return None

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get a secret value.

        Search order:
        1. Environment variables
        2. OS keychain
        3. Encrypted file cache
        4. Default value

        Args:
            key: The secret key to retrieve.
            default: Default value if secret not found.

        Returns:
            The secret value or default if not found.

        Raises:
            Exception: If keychain lookup fails (exception is caught; search continues).
        """
        if value := os.getenv(key):
            return value

        if value := self._get_from_keyring(key):
            return value

        return self._cache.get(key) or default

    def set(self, key: str, value: str, use_keychain: bool = True) -> None:
        """Set a secret value.

        Stores secret in cache, attempts keyring storage, and persists to
        encrypted file. Updates configuration metadata.

        Args:
            key: Secret key.
            value: Secret value.
            use_keychain: Whether to try storing in OS keychain.

        Raises:
            Exception: If keyring storage fails (exception is caught; file storage
                continues) or if file saving or metadata sync fails (exceptions are
                caught and logged).
        """
        # Update cache
        self._cache[key] = value

        # Try to store in keychain if available
        if use_keychain and HAS_KEYRING and keyring_module is not None:
            try:
                keyring_module.set_password(self.SERVICE_NAME, key, value)
                logger.debug("Stored secret in OS keychain")
            except Exception:
                logger.warning("Failed to store secret in keychain", exc_info=True)

        # Always save to encrypted file as backup
        self._save_secrets()

        # Sync metadata to central config
        self._sync_metadata_to_central_config()

    def delete(self, key: str) -> None:
        """Delete a secret.

        Removes secret from cache, keychain, and persists changes.
        Updates configuration metadata.

        Args:
            key: The secret key to delete.

        Raises:
            Exception: If keychain deletion fails (exception is caught; file saving
                continues) or if file saving or metadata sync fails (exceptions are
                caught and logged).
        """
        # Remove from cache
        self._cache.pop(key, None)

        # Try to remove from keychain if available
        if HAS_KEYRING and keyring_module is not None:
            try:
                keyring_module.delete_password(self.SERVICE_NAME, key)
            except Exception as e:
                logger.exception("Exception in secrets_manager: %s", e, exc_info=True)
                # Ignore if not in keychain

        # Save updated cache
        self._save_secrets()

        # Sync metadata to central config
        self._sync_metadata_to_central_config()

    def list_keys(self) -> list[str]:
        """List all available secret keys.

        Returns:
            Sorted list of all available secret key names from all backends.

        Raises:
            Exception: If retrieving environment variable values fails (exception is
                caught; keyring fallback is used).
        """
        keys = {key for key in self.KNOWN_SECRETS if os.getenv(key)} | set(self._cache)
        return sorted(keys)

    def export_secrets(self, include_values: bool = False) -> dict[str, Any]:
        """Export secrets configuration.

        Args:
            include_values: Whether to include actual values (dangerous!).

        Returns:
            Dictionary of secrets (values redacted by default).

        Raises:
            Exception: If retrieving secret values fails (exception is caught; None is
                used as the value).
        """
        result = {}

        for key in self.list_keys():
            value = self.get(key)
            if include_values:
                redacted_value = value
            else:
                redacted_value = value[:4] + "*" * max(0, len(value) - 4) if value else None
            result[key] = redacted_value

        return result

    def import_secrets(self, secrets: dict[str, str], use_keychain: bool = True) -> None:
        """Import secrets from a dictionary.

        Skips importing redacted values (those ending with asterisks).

        Args:
            secrets: Dictionary of key-value pairs to import.
            use_keychain: Whether to store imported secrets in OS keychain.

        Raises:
            Exception: If storing secrets fails (exception is caught and logged in the
                set() method).
        """
        for key, value in secrets.items():
            if value and not value.endswith("*" * 4):  # Skip redacted values
                self.set(key, value, use_keychain)

    def get_api_key(self, service: str) -> str | None:
        """Get API key for a specific service.

        Common service names are mapped to their environment variables.

        Args:
            service: The service name (e.g., 'openai', 'anthropic', 'google').

        Returns:
            The API key for the service, or None if not found.

        Raises:
            Exception: If secret retrieval fails (exception is caught; search continues).
        """
        # Map common service names to env vars
        service_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "google": "GOOGLE_API_KEY",
            "cohere": "COHERE_API_KEY",
            "huggingface": "HUGGINGFACE_API_TOKEN",
            "groq": "GROQ_API_KEY",
            "together": "TOGETHER_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }

        # Normalize service name
        service_lower = service.lower().replace("-", "_").replace(" ", "_")

        # Try mapped name first
        if service_lower in service_map:
            return self.get(service_map[service_lower])

        # Try direct lookup or generic
        return self.get(f"{service_lower.upper()}_API_KEY") or self.get("API_KEY")

    def rotate_key(self, old_key: str, new_key: str) -> None:
        """Rotate a secret key.

        Copies secret value from old key to new key, then deletes the old key.

        Args:
            old_key: The current secret key name.
            new_key: The new secret key name.

        Raises:
            Exception: If setting or deleting secrets fails (exceptions are caught and
                logged).
        """
        if value := self.get(old_key):
            self.set(new_key, value)
            self.delete(old_key)
            logger.info("Rotated secret from %s to %s", old_key, new_key)

    def clear_cache(self) -> None:
        """Clear the in-memory secrets cache.

        Removes all secrets from the in-memory cache without affecting
        persisted secrets in files or keychains.

        Raises:
            Exception: If logging the action fails (though logging exceptions are
                typically suppressed).
        """
        self._cache.clear()
        logger.info("Cleared secrets cache")

    def generate_key_from_password(self, password: str, salt: bytes | None = None) -> bytes:
        """Generate a key from password using PBKDF2HMAC and hashes.

        Args:
            password: The password to derive key from.
            salt: Optional salt bytes (random salt generated if None).

        Returns:
            Derived key bytes.

        Raises:
            Exception: If cryptography library is unavailable or key derivation fails
                (empty bytes returned if unavailable; exception raised if derivation
                fails).
        """
        if not HAS_CRYPTOGRAPHY or PBKDF2HMAC is None or hashes is None:
            logger.exception("Cryptography library not available for key generation")
            return b""

        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return cast("bytes", kdf.derive(password.encode()))

    def find_env_file_location(self) -> str | None:
        """Find .env file location using find_dotenv.

        Returns:
            Path to .env file or None if not found.

        Raises:
            Exception: If finding .env file fails (exception is caught and logged; None
                is returned).
        """
        if not HAS_DOTENV or find_dotenv is None:
            logger.warning("python-dotenv not available for finding .env files")
            return None

        try:
            env_path = cast("str | None", find_dotenv())
            if env_path:
                logger.info("Found .env file at: %s", env_path)
                return env_path
            logger.info("No .env file found in search path")
            return None
        except Exception as e:
            logger.exception("Error finding .env file: %s", e, exc_info=True)
            return None

    def verify_password_hash(self, password: str, stored_hash: bytes, salt: bytes) -> bool:
        """Verify password against stored hash using hashes.

        Args:
            password: Password to verify.
            stored_hash: Stored hash bytes.
            salt: Salt used for hashing.

        Returns:
            True if password matches, False otherwise.

        Raises:
            Exception: If cryptography library is unavailable (False returned) or if
                hash verification fails (exception is caught and logged; False returned).
        """
        if not HAS_CRYPTOGRAPHY or PBKDF2HMAC is None or hashes is None:
            logger.exception("Cryptography library not available for password verification")
            return False

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = cast("bytes", kdf.derive(password.encode()))

            return derived_key == stored_hash
        except Exception as e:
            logger.exception("Error verifying password hash: %s", e, exc_info=True)
            return False

    def _sync_metadata_to_central_config(self) -> None:
        """Sync encrypted keys metadata to central config.

        Updates central config with information about stored secrets including
        key names, types (API keys, tokens), and keychain status.

        Raises:
            Exception: If setting configuration values or checking keychain fails
                (exceptions are caught and logged as warnings).
        """
        try:
            # Build metadata about encrypted keys
            encrypted_keys_list: list[dict[str, Any]] = []
            last_sync: float | None = self.secrets_file.stat().st_mtime if self.secrets_file.exists() else None

            # Add key names (but not values) to metadata
            for key in self._cache:
                key_info: dict[str, Any] = {
                    "name": key,
                    "is_api_key": key.endswith(("_API_KEY", "_API_TOKEN", "_KEY", "_TOKEN")),
                    "in_keychain": False,
                }

                # Check if key is in keychain
                if HAS_KEYRING and keyring_module is not None:
                    try:
                        keychain_value = keyring_module.get_password(self.SERVICE_NAME, key)
                        key_info["in_keychain"] = bool(keychain_value)
                    except Exception as e:
                        logger.debug("Error checking keychain: %s", e, exc_info=True)

                encrypted_keys_list.append(key_info)

            # Store metadata in central config
            self.central_config.set("secrets.encrypted_keys", encrypted_keys_list)
            self.central_config.set("secrets.total_keys", len(self._cache))
            self.central_config.set("secrets.last_sync", last_sync)

            logger.debug("Synced %s keys metadata to central config", len(self._cache))
        except Exception as e:
            logger.warning("Could not sync keys metadata to central config: %s", e, exc_info=True)


# Singleton instance
_secrets_manager: SecretsManager | None = None


def get_secrets_manager() -> SecretsManager:
    """Get the singleton secrets manager instance.

    Returns:
        The global SecretsManager singleton instance.

    Raises:
        Exception: If SecretsManager initialization fails (exception is raised to
            caller).
    """
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Convenience functions
def get_secret(key: str, default: str | None = None) -> str | None:
    """Get a secret value.

    Args:
        key: The secret key to retrieve.
        default: Default value if secret not found.

    Returns:
        The secret value or default if not found.

    Raises:
        Exception: If secrets manager initialization or retrieval fails (exception is
            raised to caller).
    """
    return get_secrets_manager().get(key, default)


def set_secret(key: str, value: str, use_keychain: bool = True) -> None:
    """Set a secret value.

    Args:
        key: The secret key.
        value: The secret value.
        use_keychain: Whether to store in OS keychain.

    Raises:
        Exception: If secrets manager initialization or storage fails (exception is
            raised to caller).
    """
    get_secrets_manager().set(key, value, use_keychain)


def get_api_key(service: str) -> str | None:
    """Get API key for a service.

    Args:
        service: The service name (e.g., 'openai', 'anthropic').

    Returns:
        The API key for the service, or None if not found.

    Raises:
        Exception: If secrets manager initialization or retrieval fails (exception is
            raised to caller).
    """
    return get_secrets_manager().get_api_key(service)
