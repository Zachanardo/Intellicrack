"""Production-ready tests for intellicrack/utils/secrets_manager.py

Tests validate REAL secrets management capabilities:
- Secure encryption/decryption using Fernet
- OS keychain integration (Windows Credential Manager)
- Environment variable loading from .env files
- Password-based key derivation using PBKDF2HMAC
- Key rotation and management
- Fallback mechanisms when dependencies unavailable
- File permission security (0o600)
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.utils.secrets_manager import (
    SecretsManager,
    get_api_key,
    get_secret,
    get_secrets_manager,
    set_secret,
)


class TestSecretsManagerInitialization:
    """Test secrets manager initialization and configuration."""

    def test_secrets_manager_initializes_with_default_config_dir(self) -> None:
        """Secrets manager creates default config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.SecretsManager._get_default_config_dir", return_value=config_dir):
                manager = SecretsManager()

                assert manager.config_dir == config_dir
                assert manager.config_dir.exists()
                assert manager.secrets_file == config_dir / "secrets.enc"
                assert manager.key_file == config_dir / ".key"

    def test_secrets_manager_initializes_with_custom_config_dir(self) -> None:
        """Secrets manager accepts custom config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_dir = Path(tmpdir) / "custom_config"
            manager = SecretsManager(config_dir=custom_dir)

            assert manager.config_dir == custom_dir
            assert custom_dir.exists()

    def test_secrets_manager_creates_encryption_key_on_first_run(self) -> None:
        """Secrets manager generates encryption key on first initialization."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            assert manager.key_file.exists()
            key_data = manager.key_file.read_bytes()
            assert len(key_data) > 0

    def test_secrets_manager_sets_restrictive_permissions_on_key_file(self) -> None:
        """Secrets manager sets 0o600 permissions on key file for security."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        if os.name == "nt":
            pytest.skip("Unix permissions not applicable on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            key_stat = manager.key_file.stat()
            assert oct(key_stat.st_mode).endswith("600")


class TestSecretsManagerEncryption:
    """Test encryption and decryption functionality."""

    def test_encrypts_secrets_when_saving_to_file(self) -> None:
        """Secrets manager encrypts secrets before writing to file."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            test_secret = "super_secret_api_key_12345"
            manager.set("TEST_API_KEY", test_secret, use_keychain=False)

            encrypted_data = manager.secrets_file.read_bytes()
            assert test_secret.encode() not in encrypted_data

    def test_decrypts_secrets_when_loading_from_file(self) -> None:
        """Secrets manager decrypts secrets when loading from file."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            test_secret = "encrypted_secret_value"
            manager1 = SecretsManager(config_dir=config_dir)
            manager1.set("TEST_SECRET", test_secret, use_keychain=False)

            manager2 = SecretsManager(config_dir=config_dir)
            retrieved_secret = manager2.get("TEST_SECRET")

            assert retrieved_secret == test_secret

    def test_handles_corrupted_encrypted_file_gracefully(self) -> None:
        """Secrets manager handles corrupted encrypted files without crashing."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            manager.secrets_file.write_bytes(b"corrupted_data_not_valid_fernet")

            manager._load_secrets()
            assert isinstance(manager._cache, dict)

    def test_falls_back_to_plaintext_when_encryption_unavailable(self) -> None:
        """Secrets manager stores plaintext when cryptography unavailable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.HAS_CRYPTOGRAPHY", False):
                manager = SecretsManager(config_dir=config_dir)
                manager.set("PLAIN_SECRET", "plaintext_value", use_keychain=False)

                file_content = manager.secrets_file.read_text()
                data = json.loads(file_content)
                assert data["PLAIN_SECRET"] == "plaintext_value"


class TestSecretsManagerKeychain:
    """Test OS keychain integration."""

    def test_stores_secret_in_keychain_when_available(self) -> None:
        """Secrets manager stores secrets in OS keychain when available."""
        from intellicrack.utils.secrets_manager import HAS_KEYRING

        if not HAS_KEYRING:
            pytest.skip("Keyring not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            test_value = "keychain_secret_123"
            with patch("intellicrack.utils.secrets_manager.keyring") as mock_keyring:
                mock_keyring.set_password = MagicMock()
                manager.set("KEYCHAIN_TEST", test_value, use_keychain=True)

                mock_keyring.set_password.assert_called_once()

    def test_retrieves_secret_from_keychain_with_priority(self) -> None:
        """Secrets manager retrieves from keychain before encrypted file."""
        from intellicrack.utils.secrets_manager import HAS_KEYRING

        if not HAS_KEYRING:
            pytest.skip("Keyring not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.keyring") as mock_keyring:
                mock_keyring.get_password = MagicMock(return_value="keychain_value")

                manager = SecretsManager(config_dir=config_dir)
                manager._cache["TEST_KEY"] = "file_value"

                result = manager.get("TEST_KEY")
                assert result == "keychain_value"

    def test_deletes_secret_from_keychain_when_deleted(self) -> None:
        """Secrets manager removes secret from keychain on delete."""
        from intellicrack.utils.secrets_manager import HAS_KEYRING

        if not HAS_KEYRING:
            pytest.skip("Keyring not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.keyring") as mock_keyring:
                mock_keyring.delete_password = MagicMock()

                manager = SecretsManager(config_dir=config_dir)
                manager._cache["DELETE_TEST"] = "value"
                manager.delete("DELETE_TEST")

                mock_keyring.delete_password.assert_called_once()


class TestSecretsManagerEnvironmentVariables:
    """Test environment variable loading and priority."""

    def test_loads_secret_from_environment_variable(self) -> None:
        """Secrets manager loads secrets from environment variables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            env_value = "env_secret_value"
            with patch.dict(os.environ, {"ENV_TEST_KEY": env_value}):
                manager = SecretsManager(config_dir=config_dir)
                result = manager.get("ENV_TEST_KEY")
                assert result == env_value

    def test_environment_variable_has_highest_priority(self) -> None:
        """Environment variables override keychain and file cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            env_value = "env_priority_value"
            with patch.dict(os.environ, {"PRIORITY_TEST": env_value}):
                manager = SecretsManager(config_dir=config_dir)
                manager._cache["PRIORITY_TEST"] = "cache_value"

                result = manager.get("PRIORITY_TEST")
                assert result == env_value

    def test_loads_dotenv_file_when_available(self) -> None:
        """Secrets manager loads .env files when dotenv available."""
        from intellicrack.utils.secrets_manager import HAS_DOTENV

        if not HAS_DOTENV:
            pytest.skip("dotenv not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("DOTENV_TEST_KEY=dotenv_value\n")

            with patch("intellicrack.utils.secrets_manager.find_dotenv", return_value=str(env_file)):
                with patch("intellicrack.utils.secrets_manager.load_dotenv") as mock_load:
                    config_dir = Path(tmpdir) / "test_secrets"
                    SecretsManager(config_dir=config_dir)
                    assert mock_load.called


class TestSecretsManagerAPIKeyRetrieval:
    """Test API key retrieval for different services."""

    def test_get_api_key_for_openai(self) -> None:
        """Secrets manager retrieves OpenAI API key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            openai_key = "sk-openai123456"
            with patch.dict(os.environ, {"OPENAI_API_KEY": openai_key}):
                manager = SecretsManager(config_dir=config_dir)
                result = manager.get_api_key("openai")
                assert result == openai_key

    def test_get_api_key_for_anthropic(self) -> None:
        """Secrets manager retrieves Anthropic API key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            anthropic_key = "sk-ant-api123456"
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": anthropic_key}):
                manager = SecretsManager(config_dir=config_dir)
                result = manager.get_api_key("anthropic")
                assert result == anthropic_key

    def test_get_api_key_normalizes_service_name(self) -> None:
        """Secrets manager normalizes service names (case, spaces, hyphens)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            google_key = "google_key_123"
            with patch.dict(os.environ, {"GOOGLE_API_KEY": google_key}):
                manager = SecretsManager(config_dir=config_dir)

                assert manager.get_api_key("Google") == google_key
                assert manager.get_api_key("GOOGLE") == google_key
                assert manager.get_api_key("google") == google_key

    def test_get_api_key_falls_back_to_generic_key(self) -> None:
        """Secrets manager falls back to generic API_KEY for unknown services."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            generic_key = "generic_api_key_123"
            with patch.dict(os.environ, {"API_KEY": generic_key}):
                manager = SecretsManager(config_dir=config_dir)
                result = manager.get_api_key("unknown_service")
                assert result == generic_key


class TestSecretsManagerKeyManagement:
    """Test key listing, rotation, and deletion."""

    def test_list_keys_returns_all_available_keys(self) -> None:
        """Secrets manager lists all available secret keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch.dict(os.environ, {"ENV_KEY_1": "value1", "OPENAI_API_KEY": "value2"}):
                manager = SecretsManager(config_dir=config_dir)
                manager.set("FILE_KEY_1", "value3", use_keychain=False)
                manager.set("FILE_KEY_2", "value4", use_keychain=False)

                keys = manager.list_keys()
                assert "ENV_KEY_1" in keys
                assert "OPENAI_API_KEY" in keys
                assert "FILE_KEY_1" in keys
                assert "FILE_KEY_2" in keys

    def test_rotate_key_moves_secret_to_new_name(self) -> None:
        """Secrets manager rotates keys by moving to new name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            old_value = "old_key_value"
            manager.set("OLD_KEY", old_value, use_keychain=False)
            manager.rotate_key("OLD_KEY", "NEW_KEY")

            assert manager.get("NEW_KEY") == old_value
            assert manager.get("OLD_KEY") is None

    def test_delete_removes_secret_from_cache(self) -> None:
        """Secrets manager removes secret from cache on delete."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            manager.set("DELETE_ME", "value_to_delete", use_keychain=False)
            assert manager.get("DELETE_ME") == "value_to_delete"

            manager.delete("DELETE_ME")
            assert manager.get("DELETE_ME") is None

    def test_clear_cache_removes_all_cached_secrets(self) -> None:
        """Secrets manager clears all cached secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            manager.set("KEY1", "value1", use_keychain=False)
            manager.set("KEY2", "value2", use_keychain=False)
            assert len(manager._cache) == 2

            manager.clear_cache()
            assert len(manager._cache) == 0


class TestSecretsManagerImportExport:
    """Test secrets import and export functionality."""

    def test_export_secrets_redacts_values_by_default(self) -> None:
        """Secrets manager exports with redacted values by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            manager.set("EXPORT_KEY", "secret_value_12345", use_keychain=False)
            exported = manager.export_secrets(include_values=False)

            assert "EXPORT_KEY" in exported
            assert exported["EXPORT_KEY"].startswith("secr")
            assert "*" in exported["EXPORT_KEY"]
            assert "12345" not in exported["EXPORT_KEY"]

    def test_export_secrets_includes_values_when_requested(self) -> None:
        """Secrets manager exports full values when explicitly requested."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            secret_value = "full_secret_value"
            manager.set("FULL_EXPORT", secret_value, use_keychain=False)
            exported = manager.export_secrets(include_values=True)

            assert exported["FULL_EXPORT"] == secret_value

    def test_import_secrets_loads_dictionary_of_secrets(self) -> None:
        """Secrets manager imports secrets from dictionary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            secrets_to_import = {
                "IMPORT_KEY_1": "value1",
                "IMPORT_KEY_2": "value2",
                "IMPORT_KEY_3": "value3",
            }

            manager.import_secrets(secrets_to_import, use_keychain=False)

            assert manager.get("IMPORT_KEY_1") == "value1"
            assert manager.get("IMPORT_KEY_2") == "value2"
            assert manager.get("IMPORT_KEY_3") == "value3"

    def test_import_secrets_skips_redacted_values(self) -> None:
        """Secrets manager skips redacted values during import."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            secrets_with_redacted = {
                "REAL_VALUE": "actual_secret",
                "REDACTED_VALUE": "test****",
            }

            manager.import_secrets(secrets_with_redacted, use_keychain=False)

            assert manager.get("REAL_VALUE") == "actual_secret"
            assert manager.get("REDACTED_VALUE") is None


class TestSecretsManagerPasswordHashing:
    """Test password-based key derivation and verification."""

    def test_generate_key_from_password_produces_consistent_key(self) -> None:
        """Password-based key derivation produces consistent keys with same salt."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            password = "test_password_123"
            salt = os.urandom(16)

            key1 = manager.generate_key_from_password(password, salt)
            key2 = manager.generate_key_from_password(password, salt)

            assert key1 == key2
            assert len(key1) == 32

    def test_generate_key_from_password_produces_different_keys_with_different_salts(self) -> None:
        """Password-based key derivation produces different keys with different salts."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            password = "same_password"
            salt1 = os.urandom(16)
            salt2 = os.urandom(16)

            key1 = manager.generate_key_from_password(password, salt1)
            key2 = manager.generate_key_from_password(password, salt2)

            assert key1 != key2

    def test_verify_password_hash_validates_correct_password(self) -> None:
        """Password verification succeeds with correct password."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            password = "correct_password"
            salt = os.urandom(16)
            stored_hash = manager.generate_key_from_password(password, salt)

            assert manager.verify_password_hash(password, stored_hash, salt) is True

    def test_verify_password_hash_rejects_incorrect_password(self) -> None:
        """Password verification fails with incorrect password."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            correct_password = "correct_password"
            wrong_password = "wrong_password"
            salt = os.urandom(16)
            stored_hash = manager.generate_key_from_password(correct_password, salt)

            assert manager.verify_password_hash(wrong_password, stored_hash, salt) is False


class TestSecretsManagerSingletonFunctions:
    """Test global singleton functions."""

    def test_get_secrets_manager_returns_singleton_instance(self) -> None:
        """get_secrets_manager returns same instance on repeated calls."""
        manager1 = get_secrets_manager()
        manager2 = get_secrets_manager()
        assert manager1 is manager2

    def test_get_secret_convenience_function_retrieves_value(self) -> None:
        """get_secret convenience function retrieves secret value."""
        test_value = "convenience_test_value"
        with patch.dict(os.environ, {"CONVENIENCE_TEST": test_value}):
            result = get_secret("CONVENIENCE_TEST")
            assert result == test_value

    def test_set_secret_convenience_function_stores_value(self) -> None:
        """set_secret convenience function stores secret value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("intellicrack.utils.secrets_manager._secrets_manager", None):
                with patch("intellicrack.utils.secrets_manager.SecretsManager._get_default_config_dir", return_value=Path(tmpdir)):
                    set_secret("CONV_SET_TEST", "stored_value", use_keychain=False)
                    result = get_secret("CONV_SET_TEST")
                    assert result == "stored_value"

    def test_get_api_key_convenience_function_retrieves_service_key(self) -> None:
        """get_api_key convenience function retrieves API key for service."""
        test_key = "openai_test_key"
        with patch.dict(os.environ, {"OPENAI_API_KEY": test_key}):
            result = get_api_key("openai")
            assert result == test_key


class TestSecretsManagerFilePermissions:
    """Test file permission security."""

    def test_secrets_file_has_restrictive_permissions(self) -> None:
        """Secrets file has 0o600 permissions after save."""
        from intellicrack.utils.secrets_manager import HAS_CRYPTOGRAPHY

        if not HAS_CRYPTOGRAPHY:
            pytest.skip("Cryptography not available")

        if os.name == "nt":
            pytest.skip("Unix permissions not applicable on Windows")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"
            manager = SecretsManager(config_dir=config_dir)

            manager.set("PERM_TEST", "value", use_keychain=False)

            secrets_stat = manager.secrets_file.stat()
            assert oct(secrets_stat.st_mode).endswith("600")


class TestSecretsManagerDotenvIntegration:
    """Test .env file discovery and loading."""

    def test_find_env_file_location_discovers_dotenv(self) -> None:
        """Secrets manager discovers .env file location."""
        from intellicrack.utils.secrets_manager import HAS_DOTENV

        if not HAS_DOTENV:
            pytest.skip("dotenv not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("TEST_VAR=value\n")

            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.find_dotenv", return_value=str(env_file)):
                manager = SecretsManager(config_dir=config_dir)
                location = manager.find_env_file_location()
                assert location == str(env_file)

    def test_find_env_file_location_returns_none_when_not_found(self) -> None:
        """Secrets manager returns None when .env file not found."""
        from intellicrack.utils.secrets_manager import HAS_DOTENV

        if not HAS_DOTENV:
            pytest.skip("dotenv not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "test_secrets"

            with patch("intellicrack.utils.secrets_manager.find_dotenv", return_value=None):
                manager = SecretsManager(config_dir=config_dir)
                location = manager.find_env_file_location()
                assert location is None
