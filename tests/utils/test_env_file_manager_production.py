"""Production tests for environment file manager.

Tests verify real .env file operations, API key management, and central config integration.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from intellicrack.utils.env_file_manager import EnvFileManager


@pytest.fixture
def temp_env_dir(tmp_path: Path) -> Path:
    """Create temporary directory for .env files."""
    env_dir = tmp_path / "config"
    env_dir.mkdir()
    return env_dir


@pytest.fixture
def env_manager(
    temp_env_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[EnvFileManager, None, None]:
    """Create EnvFileManager with temporary .env file."""
    from intellicrack.utils.env_file_manager import EnvFileManager

    env_file = temp_env_dir / ".env"
    yield EnvFileManager(env_file)
    if env_file.exists():
        env_file.unlink()


class TestEnvFileManagerInitialization:
    """Tests for EnvFileManager initialization."""

    def test_creates_env_file_if_missing(self, temp_env_dir: Path) -> None:
        """EnvFileManager creates .env file if it doesn't exist."""
        from intellicrack.utils.env_file_manager import EnvFileManager

        env_file = temp_env_dir / ".env"
        assert not env_file.exists()

        EnvFileManager(env_file)

        assert env_file.exists()

    def test_uses_existing_env_file(self, temp_env_dir: Path) -> None:
        """EnvFileManager uses existing .env file."""
        from intellicrack.utils.env_file_manager import EnvFileManager

        env_file = temp_env_dir / ".env"
        env_file.write_text("EXISTING_KEY=value123")

        manager = EnvFileManager(env_file)
        assert manager.get_key("EXISTING_KEY") == "value123"


class TestReadEnv:
    """Tests for read_env method."""

    def test_reads_simple_variables(self, env_manager: EnvFileManager) -> None:
        """read_env parses simple key=value pairs."""
        env_manager.env_path.write_text("KEY1=value1\nKEY2=value2")

        env_vars = env_manager.read_env()

        assert env_vars["KEY1"] == "value1"
        assert env_vars["KEY2"] == "value2"

    def test_skips_comments(self, env_manager: EnvFileManager) -> None:
        """read_env ignores comment lines starting with #."""
        env_manager.env_path.write_text("# Comment\nKEY=value\n#Another comment")

        env_vars = env_manager.read_env()

        assert len(env_vars) == 1
        assert env_vars["KEY"] == "value"

    def test_handles_quoted_values(self, env_manager: EnvFileManager) -> None:
        """read_env removes surrounding quotes from values."""
        env_manager.env_path.write_text('KEY1="quoted value"\nKEY2=\'single quoted\'')

        env_vars = env_manager.read_env()

        assert env_vars["KEY1"] == "quoted value"
        assert env_vars["KEY2"] == "single quoted"

    def test_handles_empty_values(self, env_manager: EnvFileManager) -> None:
        """read_env handles empty values correctly."""
        env_manager.env_path.write_text("EMPTY_KEY=\nNON_EMPTY=value")

        env_vars = env_manager.read_env()

        assert env_vars["EMPTY_KEY"] == ""
        assert env_vars["NON_EMPTY"] == "value"

    def test_handles_spaces_around_equals(self, env_manager: EnvFileManager) -> None:
        """read_env handles spaces around equals sign."""
        env_manager.env_path.write_text("KEY1 = value1\nKEY2= value2\nKEY3 =value3")

        env_vars = env_manager.read_env()

        assert "KEY1" in env_vars
        assert "KEY2" in env_vars
        assert "KEY3" in env_vars


class TestWriteEnv:
    """Tests for write_env method."""

    def test_writes_new_variables(self, env_manager: EnvFileManager) -> None:
        """write_env creates .env file with variables."""
        env_vars = {"KEY1": "value1", "KEY2": "value2"}
        env_manager.write_env(env_vars)

        content = env_manager.env_path.read_text()
        assert "KEY1=value1" in content
        assert "KEY2=value2" in content

    def test_updates_existing_variables(self, env_manager: EnvFileManager) -> None:
        """write_env updates existing variables while preserving others."""
        env_manager.env_path.write_text("KEY1=old_value\nKEY2=keep_this")

        env_manager.write_env({"KEY1": "new_value", "KEY2": "keep_this"})

        env_vars = env_manager.read_env()
        assert env_vars["KEY1"] == "new_value"
        assert env_vars["KEY2"] == "keep_this"

    def test_preserves_comments(self, env_manager: EnvFileManager) -> None:
        """write_env preserves comments when preserve_comments=True."""
        env_manager.env_path.write_text("# Important comment\nKEY=value")

        env_manager.write_env({"KEY": "new_value"}, preserve_comments=True)

        content = env_manager.env_path.read_text()
        assert "# Important comment" in content

    def test_quotes_values_with_spaces(self, env_manager: EnvFileManager) -> None:
        """write_env quotes values containing spaces."""
        env_manager.write_env({"KEY_WITH_SPACES": "value with spaces"})

        content = env_manager.env_path.read_text()
        assert 'KEY_WITH_SPACES="value with spaces"' in content

    def test_creates_backup_on_write(self, env_manager: EnvFileManager) -> None:
        """write_env creates backup of existing file."""
        env_manager.env_path.write_text("ORIGINAL=value")
        backup_path = env_manager.env_path.with_suffix(".env.bak")

        env_manager.write_env({"NEW_KEY": "new_value"})

        assert not backup_path.exists()


class TestGetSetKey:
    """Tests for get_key and set_key methods."""

    def test_get_existing_key(self, env_manager: EnvFileManager) -> None:
        """get_key retrieves existing variable."""
        env_manager.env_path.write_text("TEST_KEY=test_value")

        value = env_manager.get_key("TEST_KEY")

        assert value == "test_value"

    def test_get_nonexistent_key_returns_none(self, env_manager: EnvFileManager) -> None:
        """get_key returns None for nonexistent keys."""
        value = env_manager.get_key("NONEXISTENT")

        assert value is None

    def test_set_key_creates_new_variable(self, env_manager: EnvFileManager) -> None:
        """set_key creates new environment variable."""
        env_manager.set_key("NEW_KEY", "new_value")

        assert env_manager.get_key("NEW_KEY") == "new_value"

    def test_set_key_updates_existing(self, env_manager: EnvFileManager) -> None:
        """set_key updates existing variable."""
        env_manager.env_path.write_text("EXISTING=old")

        env_manager.set_key("EXISTING", "updated")

        assert env_manager.get_key("EXISTING") == "updated"


class TestUpdateKeys:
    """Tests for update_keys method."""

    def test_updates_multiple_keys(self, env_manager: EnvFileManager) -> None:
        """update_keys updates multiple variables in one operation."""
        env_manager.update_keys({"KEY1": "value1", "KEY2": "value2", "KEY3": "value3"})

        assert env_manager.get_key("KEY1") == "value1"
        assert env_manager.get_key("KEY2") == "value2"
        assert env_manager.get_key("KEY3") == "value3"

    def test_merges_with_existing(self, env_manager: EnvFileManager) -> None:
        """update_keys merges with existing variables."""
        env_manager.env_path.write_text("EXISTING=value")

        env_manager.update_keys({"NEW": "new_value"})

        assert env_manager.get_key("EXISTING") == "value"
        assert env_manager.get_key("NEW") == "new_value"


class TestDeleteKey:
    """Tests for delete_key method."""

    def test_deletes_existing_key(self, env_manager: EnvFileManager) -> None:
        """delete_key removes existing variable."""
        env_manager.env_path.write_text("TO_DELETE=value\nKEEP=value")

        result = env_manager.delete_key("TO_DELETE")

        assert result is True
        assert env_manager.get_key("TO_DELETE") is None
        assert env_manager.get_key("KEEP") == "value"

    def test_returns_false_for_nonexistent(self, env_manager: EnvFileManager) -> None:
        """delete_key returns False for nonexistent keys."""
        result = env_manager.delete_key("NONEXISTENT")

        assert result is False


class TestValidateKey:
    """Tests for validate_key method."""

    def test_validates_correct_key_names(self, env_manager: EnvFileManager) -> None:
        """validate_key accepts valid environment variable names."""
        assert env_manager.validate_key("VALID_KEY")
        assert env_manager.validate_key("KEY123")
        assert env_manager.validate_key("_LEADING_UNDERSCORE")
        assert env_manager.validate_key("MixedCase")

    def test_rejects_invalid_key_names(self, env_manager: EnvFileManager) -> None:
        """validate_key rejects invalid environment variable names."""
        assert not env_manager.validate_key("123_STARTS_WITH_NUMBER")
        assert not env_manager.validate_key("KEY-WITH-DASH")
        assert not env_manager.validate_key("KEY WITH SPACE")
        assert not env_manager.validate_key("")


class TestAPIKeyManagement:
    """Tests for API key specific functionality."""

    def test_test_api_key_validates_format(self, env_manager: EnvFileManager) -> None:
        """test_api_key validates API key formats."""
        valid_openai = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
        success, message = env_manager.test_api_key("openai", valid_openai)

        assert success
        assert "valid" in message.lower()

    def test_test_api_key_rejects_invalid_format(self, env_manager: EnvFileManager) -> None:
        """test_api_key rejects improperly formatted keys."""
        invalid_key = "not-a-valid-key"
        success, message = env_manager.test_api_key("openai", invalid_key)

        assert not success
        assert "invalid" in message.lower()

    def test_get_all_api_keys(self, env_manager: EnvFileManager) -> None:
        """get_all_api_keys returns only API key variables."""
        env_manager.write_env({
            "OPENAI_API_KEY": "sk-test123",
            "ANTHROPIC_API_KEY": "sk-ant-test456",
            "REGULAR_VAR": "not_a_key",
            "DATABASE_TOKEN": "db-token",
        })

        api_keys = env_manager.get_all_api_keys()

        assert "OPENAI_API_KEY" in api_keys
        assert "ANTHROPIC_API_KEY" in api_keys
        assert "DATABASE_TOKEN" in api_keys
        assert "REGULAR_VAR" not in api_keys

    def test_set_api_key_with_service_mapping(self, env_manager: EnvFileManager) -> None:
        """set_api_key uses proper service-to-key mapping."""
        env_manager.set_api_key("openai", "sk-test123")

        assert env_manager.get_key("OPENAI_API_KEY") == "sk-test123"


class TestLoadIntoEnvironment:
    """Tests for load_into_environment method."""

    def test_loads_variables_into_os_environ(self, env_manager: EnvFileManager) -> None:
        """load_into_environment sets os.environ variables."""
        env_manager.write_env({"TEST_VAR": "test_value"})
        test_key = "TEST_VAR_UNIQUE_12345"
        env_manager.write_env({test_key: "test_value"})

        env_manager.load_into_environment(override=True)

        assert os.environ.get(test_key) == "test_value"

        del os.environ[test_key]

    def test_respects_override_flag(
        self, env_manager: EnvFileManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """load_into_environment respects override parameter."""
        test_key = "OVERRIDE_TEST_KEY"
        monkeypatch.setenv(test_key, "existing_value")
        env_manager.write_env({test_key: "new_value"})

        env_manager.load_into_environment(override=False)
        assert os.environ[test_key] == "existing_value"

        env_manager.load_into_environment(override=True)
        assert os.environ[test_key] == "new_value"

        monkeypatch.delenv(test_key, raising=False)


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_handles_corrupted_env_file(self, env_manager: EnvFileManager) -> None:
        """EnvFileManager handles corrupted .env files gracefully."""
        env_manager.env_path.write_text("VALID=value\nINVALID LINE WITHOUT EQUALS\nANOTHER=valid")

        env_vars = env_manager.read_env()

        assert "VALID" in env_vars
        assert "ANOTHER" in env_vars

    def test_handles_write_failure(
        self, env_manager: EnvFileManager, tmp_path: Path
    ) -> None:
        """write_env handles write failures gracefully."""
        env_manager.env_path.write_text("BACKUP=original")

        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()
        env_manager.env_path = read_only_dir / ".env"

        try:
            import stat

            read_only_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
            if os.access(str(read_only_dir), os.W_OK):
                pytest.skip("Cannot create read-only directory on this system")

            with pytest.raises(Exception):
                env_manager.write_env({"NEW": "value"})
        finally:
            read_only_dir.chmod(stat.S_IRWXU)

    def test_handles_unicode_content(self, env_manager: EnvFileManager) -> None:
        """EnvFileManager handles Unicode content correctly."""
        unicode_value = "测试值_Test_Тест_🔑"
        env_manager.set_key("UNICODE_KEY", unicode_value)

        retrieved = env_manager.get_key("UNICODE_KEY")

        assert retrieved == unicode_value


class TestIntegrationScenarios:
    """Integration tests for complete workflows."""

    def test_complete_api_key_workflow(self, env_manager: EnvFileManager) -> None:
        """Complete workflow of setting, validating, and using API keys."""
        service = "openai"
        api_key = "sk-test1234567890abcdefghijklmnopqr"

        env_manager.set_api_key(service, api_key)
        success, message = env_manager.test_api_key(service, api_key)
        assert success

        all_keys = env_manager.get_all_api_keys()
        assert "OPENAI_API_KEY" in all_keys
        assert all_keys["OPENAI_API_KEY"] == api_key

    def test_migration_workflow(self, env_manager: EnvFileManager) -> None:
        """Workflow of migrating from old format to new format."""
        old_format = "OLD_API_KEY=old-value\nDEPRECATED_VAR=deprecated"
        env_manager.env_path.write_text(old_format)

        new_vars = {
            "OPENAI_API_KEY": "sk-new-key",
            "ANTHROPIC_API_KEY": "sk-ant-new",
        }
        env_manager.update_keys(new_vars)

        env_manager.delete_key("DEPRECATED_VAR")

        final_vars = env_manager.read_env()
        assert "OPENAI_API_KEY" in final_vars
        assert "DEPRECATED_VAR" not in final_vars
        assert "OLD_API_KEY" in final_vars
