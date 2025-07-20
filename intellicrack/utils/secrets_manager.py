"""
Centralized Secrets Management for Intellicrack

This module provides secure storage and retrieval of sensitive information
such as API keys, tokens, and passwords.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, Optional

from .logger import get_logger

logger = get_logger(__name__)

# Optional dependencies with fallbacks
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    logger.error("Import error in secrets_manager: %s", e)
    HAS_CRYPTOGRAPHY = False
    Fernet = None

try:
    import keyring
    HAS_KEYRING = True
except ImportError as e:
    logger.error("Import error in secrets_manager: %s", e)
    HAS_KEYRING = False
    keyring = None

try:
    from dotenv import find_dotenv, load_dotenv
    HAS_DOTENV = True
except ImportError as e:
    logger.error("Import error in secrets_manager: %s", e)
    HAS_DOTENV = False
    load_dotenv = None


class SecretsManager:
    """
    Centralized secrets management with multiple backend support.

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

        # Cloud Services
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_API_KEY",
        "GCP_API_KEY",

        # Analysis Services
        "VIRUSTOTAL_API_KEY",
        "HYBRID_ANALYSIS_API_KEY",
        "MALWARE_BAZAAR_API_KEY",

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
        "PRIVATE_KEY"
    ]

    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize the secrets manager."""
        self.config_dir = config_dir or self._get_default_config_dir()
        self.secrets_file = self.config_dir / "secrets.enc"
        self.key_file = self.config_dir / ".key"

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Load environment variables
        self._load_env_files()

        # Initialize encryption
        self._init_encryption()

        # Cache for loaded secrets
        self._cache: Dict[str, Any] = {}
        self._load_secrets()

    def _get_default_config_dir(self) -> Path:
        """Get platform-specific configuration directory."""
        system = platform.system()

        if system == "Windows":
            base = Path(os.environ.get("APPDATA", ""))
        elif system == "Darwin":  # macOS
            base = Path.home() / "Library" / "Application Support"
        else:  # Linux and others
            base = Path.home() / ".config"

        return base / "intellicrack" / "secrets"

    def _load_env_files(self):
        """Load environment variables from .env files."""
        if not HAS_DOTENV:
            logger.warning("python-dotenv not available - .env files will not be loaded")
            return

        # Look for .env files in order of precedence
        env_files = [
            ".env.local",      # Highest priority - user's local overrides
            ".env.production", # Production settings
            ".env",           # Default settings
            ".env.example"    # Fallback example (should not contain real secrets)
        ]

        # Find project root (where .env files typically are)
        current = Path.cwd()
        while current != current.parent:
            for env_file in env_files:
                env_path = current / env_file
                if env_path.exists():
                    load_dotenv(env_path, override=True)
                    logger.debug(f"Loaded environment from {env_path}")

            # Check if we're at project root (has intellicrack directory)
            if (current / "intellicrack").exists():
                break
            current = current.parent

    def _init_encryption(self):
        """Initialize encryption for file-based secret storage."""
        if not HAS_CRYPTOGRAPHY:
            logger.warning("Cryptography not available - secrets will be stored as plain text")
            self._cipher = None
            return

        if not self.key_file.exists():
            # Generate a new encryption key
            key = Fernet.generate_key()
            # Try to store in OS keychain first
            if HAS_KEYRING:
                try:
                    keyring.set_password(self.SERVICE_NAME, "encryption_key", key.decode())
                    # Also save to file as backup
                    self.key_file.write_bytes(key)
                    self.key_file.chmod(0o600)  # Restrict permissions
                except Exception as e:
                    logger.warning(f"Failed to store key in keychain: {e}")
                    # Fall back to file storage
                    self.key_file.write_bytes(key)
                    self.key_file.chmod(0o600)
            else:
                # No keyring, just use file
                self.key_file.write_bytes(key)
                self.key_file.chmod(0o600)

        # Load encryption key
        try:
            # Try keychain first if available
            if HAS_KEYRING:
                key_str = keyring.get_password(self.SERVICE_NAME, "encryption_key")
                if key_str:
                    self._cipher = Fernet(key_str.encode())
                    return

            # Fall back to file
            if self.key_file.exists():
                key = self.key_file.read_bytes()
                self._cipher = Fernet(key)
            else:
                # Generate runtime-only key as last resort
                self._cipher = Fernet(Fernet.generate_key())
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            # Generate runtime-only key as last resort
            self._cipher = Fernet(Fernet.generate_key())

    def _load_secrets(self):
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
                logger.error(f"Failed to load secrets file: {e}")
                self._cache = {}
        else:
            self._cache = {}

    def _save_secrets(self):
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
            logger.error(f"Failed to save secrets: {e}")

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret value.

        Search order:
        1. Environment variables
        2. OS keychain
        3. Encrypted file cache
        4. Default value
        """
        # Check environment first (highest priority)
        value = os.getenv(key)
        if value:
            return value

        # Check OS keychain if available
        if HAS_KEYRING:
            try:
                value = keyring.get_password(self.SERVICE_NAME, key)
                if value:
                    return value
            except Exception as e:
                logger.debug(f"Keychain lookup failed for {key}: {e}")

        # Check encrypted file cache
        if key in self._cache:
            return self._cache[key]

        # Return default
        return default

    def set(self, key: str, value: str, use_keychain: bool = True):
        """
        Set a secret value.

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
                logger.debug(f"Stored {key} in OS keychain")
            except Exception as e:
                logger.warning(f"Failed to store {key} in keychain: {e}")

        # Always save to encrypted file as backup
        self._save_secrets()

    def delete(self, key: str):
        """Delete a secret."""
        # Remove from cache
        self._cache.pop(key, None)

        # Try to remove from keychain if available
        if HAS_KEYRING:
            try:
                keyring.delete_password(self.SERVICE_NAME, key)
            except Exception as e:
                logger.error("Exception in secrets_manager: %s", e)
                pass  # Ignore if not in keychain

        # Save updated cache
        self._save_secrets()

    def list_keys(self) -> list:
        """List all available secret keys."""
        keys = set()

        # Add known environment variables
        for key in self.KNOWN_SECRETS:
            if os.getenv(key):
                keys.add(key)

        # Add cached keys
        keys.update(self._cache.keys())

        return sorted(list(keys))

    def export_secrets(self, include_values: bool = False) -> Dict[str, Any]:
        """
        Export secrets configuration.

        Args:
            include_values: Whether to include actual values (dangerous!)

        Returns:
            Dictionary of secrets (values redacted by default)
        """
        result = {}

        for key in self.list_keys():
            if include_values:
                result[key] = self.get(key)
            else:
                value = self.get(key)
                if value:
                    # Redact all but first 4 chars
                    result[key] = value[:4] + "*" * (len(value) - 4)
                else:
                    result[key] = None

        return result

    def import_secrets(self, secrets: Dict[str, str], use_keychain: bool = True):
        """Import secrets from a dictionary."""
        for key, value in secrets.items():
            if value and not value.endswith("*" * 4):  # Skip redacted values
                self.set(key, value, use_keychain)

    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a specific service.

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
            "virustotal": "VIRUSTOTAL_API_KEY",
            "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY"
        }

        # Normalize service name
        service_lower = service.lower().replace("-", "_").replace(" ", "_")

        # Try mapped name first
        if service_lower in service_map:
            return self.get(service_map[service_lower])

        # Try direct lookup
        api_key = self.get(f"{service_lower.upper()}_API_KEY")
        if api_key:
            return api_key

        # Try generic API_KEY
        return self.get("API_KEY")

    def rotate_key(self, old_key: str, new_key: str):
        """Rotate a secret key."""
        value = self.get(old_key)
        if value:
            self.set(new_key, value)
            self.delete(old_key)
            logger.info(f"Rotated secret from {old_key} to {new_key}")

    def clear_cache(self):
        """Clear the in-memory secrets cache."""
        self._cache.clear()
        logger.info("Cleared secrets cache")

    def generate_key_from_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Generate a key from password using PBKDF2HMAC and hashes.

        Args:
            password: The password to derive key from
            salt: Optional salt bytes (random salt generated if None)

        Returns:
            Derived key bytes
        """
        if not HAS_CRYPTOGRAPHY:
            logger.error("Cryptography library not available for key generation")
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
        key = kdf.derive(password.encode())
        return key

    def find_env_file_location(self) -> Optional[str]:
        """Find .env file location using find_dotenv.

        Returns:
            Path to .env file or None if not found
        """
        if not HAS_DOTENV:
            logger.warning("python-dotenv not available for finding .env files")
            return None

        try:
            # Use find_dotenv to locate the .env file
            env_path = find_dotenv()
            if env_path:
                logger.info(f"Found .env file at: {env_path}")
                return env_path
            else:
                logger.info("No .env file found in search path")
                return None
        except Exception as e:
            logger.error(f"Error finding .env file: {e}")
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
            logger.error("Cryptography library not available for password verification")
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
            logger.error(f"Error verifying password hash: {e}")
            return False


# Singleton instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Get the singleton secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Convenience functions
def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get a secret value."""
    return get_secrets_manager().get(key, default)


def set_secret(key: str, value: str, use_keychain: bool = True):
    """Set a secret value."""
    get_secrets_manager().set(key, value, use_keychain)


def get_api_key(service: str) -> Optional[str]:
    """Get API key for a service."""
    return get_secrets_manager().get_api_key(service)
