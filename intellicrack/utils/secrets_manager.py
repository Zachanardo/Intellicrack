"""Centralized Secrets Management for Intellicrack.

This module provides secure storage and retrieval of sensitive information
such as API keys, tokens, and passwords.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
from pathlib import Path
from typing import Any

from intellicrack.core.config_manager import IntellicrackConfig

from .logger import get_logger


logger = get_logger(__name__)

IMPORT_ERROR_MSG = "Import error in secrets_manager: %s"
CONFIG_DIR_KEY = "secrets.config_directory"
ENCRYPTION_ENABLED_KEY = "secrets.encryption_enabled"
KEYRING_IN_USE_KEY = "secrets.keyring_in_use"

# Optional dependencies with fallbacks
try:
    from intellicrack.handlers.cryptography_handler import PBKDF2HMAC, Fernet, hashes

    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)
    HAS_CRYPTOGRAPHY = False
    Fernet = None

try:
    import keyring

    HAS_KEYRING = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)
    HAS_KEYRING = False
    keyring = None

try:
    from dotenv import find_dotenv, load_dotenv

    HAS_DOTENV = True
except ImportError as e:
    logger.exception(IMPORT_ERROR_MSG, e)
    HAS_DOTENV = False
    load_dotenv = None


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
        """Initialize the secrets manager."""
        self._central_config = None
        self._config_dir_override = config_dir

        # Get config directory from central config or use provided/default
        if config_dir is None:
            config_dir_str = self.central_config.get(CONFIG_DIR_KEY)
            if not config_dir_str:
                config_dir = self._get_default_config_dir()
                config_dir_str = str(config_dir)
                # Store the default in central config
                self.central_config.set(CONFIG_DIR_KEY, config_dir_str)
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
        """Lazy load central config."""
        if self._central_config is None:
            from intellicrack.core.config_manager import get_config

            self._central_config = get_config()
        return self._central_config

    @property
    def central_config(self) -> IntellicrackConfig:
        """Get central config instance (lazy-loaded)."""
        return self._get_central_config()

    def _get_default_config_dir(self) -> Path:
        r"""Get unified configuration directory.

        Uses relative path to Intellicrack root for all platforms to ensure consistency.
        """
        import intellicrack

        root = Path(intellicrack.__file__).parent.parent
        return root / "config" / "secrets"

    def _load_env_files(self) -> None:
        """Load environment variables from .env files."""
        if not HAS_DOTENV:
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
        """Set encryption status in central config."""
        self.central_config.set(ENCRYPTION_ENABLED_KEY, enabled)
        self.central_config.set(KEYRING_IN_USE_KEY, uses_keyring)

    def _load_encryption_key(self) -> None:
        """Load encryption key from keychain or file."""
        keyring_backend = self.central_config.get("secrets.keyring_backend", "auto")
        try:
            if HAS_KEYRING and keyring_backend != "disabled":
                if key_str := keyring.get_password(self.SERVICE_NAME, "encryption_key"):
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
        """Disable encryption and set status."""
        self._set_encryption_status(False, False)
        self._cipher = None

    def _init_encryption(self) -> None:
        """Initialize encryption for file-based secret storage."""
        # Get encryption settings from central config
        use_encryption = self.central_config.get("secrets.use_encryption", True)
        keyring_backend = self.central_config.get("secrets.keyring_backend", "auto")

        if not HAS_CRYPTOGRAPHY:
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
            if HAS_KEYRING and keyring_backend != "disabled":
                try:
                    keyring.set_password(self.SERVICE_NAME, "encryption_key", key.decode())
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
        """Write encryption key to file with restricted permissions."""
        self.key_file.write_bytes(key)
        self.key_file.chmod(0o600)

    def _load_secrets(self) -> None:
        """Load secrets from encrypted file."""
        if self.secrets_file.exists():
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
        else:
            self._cache = {}

    def _save_secrets(self) -> None:
        """Save secrets to encrypted file."""
        try:
            if self._cipher is None:
                # No encryption available, save as plain text (with warning)
                logger.warning("Saving secrets as plain text - install cryptography for encryption")
                data = json.dumps(self._cache, indent=2)
                self.secrets_file.write_text(data)
            else:
                # Encrypt data
                data = json.dumps(self._cache).encode()
                encrypted_data = self._cipher.encrypt(data)
                self.secrets_file.write_bytes(encrypted_data)

            self.secrets_file.chmod(0o600)  # Restrict permissions
            logger.debug("Saved secrets to file")
        except Exception as e:
            logger.exception("Failed to save secrets: %s", e, exc_info=True)

    def _get_from_keyring(self, key: str) -> str | None:
        """Get secret from OS keychain with error handling."""
        if not HAS_KEYRING:
            return None
        try:
            return keyring.get_password(self.SERVICE_NAME, key)
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
        """
        if value := os.getenv(key):
            return value

        if value := self._get_from_keyring(key):
            return value

        return self._cache.get(key) or default

    def set(self, key: str, value: str, use_keychain: bool = True) -> None:
        """Set a secret value.

        Args:
            key: Secret key
            value: Secret value
            use_keychain: Whether to try storing in OS keychain

        """
        # Update cache
        self._cache[key] = value

        # Try to store in keychain if available
        if use_keychain and HAS_KEYRING:
            try:
                keyring.set_password(self.SERVICE_NAME, key, value)
                logger.debug("Stored secret in OS keychain")
            except Exception:
                logger.warning("Failed to store secret in keychain", exc_info=True)

        # Always save to encrypted file as backup
        self._save_secrets()

        # Sync metadata to central config
        self._sync_metadata_to_central_config()

    def delete(self, key: str) -> None:
        """Delete a secret."""
        # Remove from cache
        self._cache.pop(key, None)

        # Try to remove from keychain if available
        if HAS_KEYRING:
            try:
                keyring.delete_password(self.SERVICE_NAME, key)
            except Exception as e:
                logger.exception("Exception in secrets_manager: %s", e, exc_info=True)
                # Ignore if not in keychain

        # Save updated cache
        self._save_secrets()

        # Sync metadata to central config
        self._sync_metadata_to_central_config()

    def list_keys(self) -> list:
        """List all available secret keys."""
        keys = {key for key in self.KNOWN_SECRETS if os.getenv(key)} | set(self._cache)
        return sorted(keys)

    def export_secrets(self, include_values: bool = False) -> dict[str, Any]:
        """Export secrets configuration.

        Args:
            include_values: Whether to include actual values (dangerous!)

        Returns:
            Dictionary of secrets (values redacted by default)

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
        """Import secrets from a dictionary."""
        for key, value in secrets.items():
            if value and not value.endswith("*" * 4):  # Skip redacted values
                self.set(key, value, use_keychain)

    def get_api_key(self, service: str) -> str | None:
        """Get API key for a specific service.

        Common service names are mapped to their environment variables.
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
        """Rotate a secret key."""
        if value := self.get(old_key):
            self.set(new_key, value)
            self.delete(old_key)
            logger.info("Rotated secret from %s to %s", old_key, new_key)

    def clear_cache(self) -> None:
        """Clear the in-memory secrets cache."""
        self._cache.clear()
        logger.info("Cleared secrets cache")

    def generate_key_from_password(self, password: str, salt: bytes | None = None) -> bytes:
        """Generate a key from password using PBKDF2HMAC and hashes.

        Args:
            password: The password to derive key from
            salt: Optional salt bytes (random salt generated if None)

        Returns:
            Derived key bytes

        """
        if not HAS_CRYPTOGRAPHY:
            logger.exception("Cryptography library not available for key generation")
            return b""

        if salt is None:
            salt = os.urandom(16)

        # Use PBKDF2HMAC with SHA256 hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def find_env_file_location(self) -> str | None:
        """Find .env file location using find_dotenv.

        Returns:
            Path to .env file or None if not found

        """
        if not HAS_DOTENV:
            logger.warning("python-dotenv not available for finding .env files")
            return None

        try:
            # Use find_dotenv to locate the .env file
            if env_path := find_dotenv():
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
            password: Password to verify
            stored_hash: Stored hash bytes
            salt: Salt used for hashing

        Returns:
            True if password matches, False otherwise

        """
        if not HAS_CRYPTOGRAPHY:
            logger.exception("Cryptography library not available for password verification")
            return False

        try:
            # Generate hash from provided password using same salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(password.encode())

            # Compare with stored hash
            return derived_key == stored_hash
        except Exception as e:
            logger.exception("Error verifying password hash: %s", e, exc_info=True)
            return False

    def _sync_metadata_to_central_config(self) -> None:
        """Sync encrypted keys metadata to central config."""
        try:
            # Build metadata about encrypted keys
            metadata = {
                "total_keys": len(self._cache),
                "encrypted_keys": [],
                "last_sync": self.secrets_file.stat().st_mtime if self.secrets_file.exists() else None,
            }

            # Add key names (but not values) to metadata
            for key in self._cache:
                key_info = {
                    "name": key,
                    "is_api_key": key.endswith(("_API_KEY", "_API_TOKEN", "_KEY", "_TOKEN")),
                    "in_keychain": False,
                }

                # Check if key is in keychain
                if HAS_KEYRING:
                    try:
                        keychain_value = keyring.get_password(self.SERVICE_NAME, key)
                        key_info["in_keychain"] = bool(keychain_value)
                    except Exception as e:
                        logger.debug("Error checking keychain: %s", e, exc_info=True)

                metadata["encrypted_keys"].append(key_info)

            # Store metadata in central config
            self.central_config.set("secrets.encrypted_keys", metadata["encrypted_keys"])
            self.central_config.set("secrets.total_keys", metadata["total_keys"])
            self.central_config.set("secrets.last_sync", metadata["last_sync"])

            logger.debug("Synced %s keys metadata to central config", metadata["total_keys"])
        except Exception as e:
            logger.warning("Could not sync keys metadata to central config: %s", e, exc_info=True)


# Singleton instance
_secrets_manager: SecretsManager | None = None


def get_secrets_manager() -> SecretsManager:
    """Get the singleton secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Convenience functions
def get_secret(key: str, default: str | None = None) -> str | None:
    """Get a secret value."""
    return get_secrets_manager().get(key, default)


def set_secret(key: str, value: str, use_keychain: bool = True) -> None:
    """Set a secret value."""
    get_secrets_manager().set(key, value, use_keychain)


def get_api_key(service: str) -> str | None:
    """Get API key for a service."""
    return get_secrets_manager().get_api_key(service)
