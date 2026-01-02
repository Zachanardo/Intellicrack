"""Production tests for security utilities.

Tests validate secure hash generation, subprocess execution, YAML/JSON loading,
file path validation, and input sanitization.
"""

import json
import subprocess

import pytest
import yaml

from intellicrack.core.security_utils import (
    SecurityError,
    sanitize_input,
    secure_hash,
    secure_json_load,
    secure_subprocess,
    secure_yaml_load,
    validate_file_path,
)


class TestSecureHash:
    """Test secure hash generation."""

    def test_secure_hash_sha256_with_string(self) -> None:
        """Secure hash generates SHA256 for string input."""
        result = secure_hash("test data", algorithm="sha256")

        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_secure_hash_sha256_with_bytes(self) -> None:
        """Secure hash generates SHA256 for bytes input."""
        result = secure_hash(b"test data", algorithm="sha256")

        assert len(result) == 64
        assert isinstance(result, str)

    def test_secure_hash_sha512(self) -> None:
        """Secure hash generates SHA512 when specified."""
        result = secure_hash("test data", algorithm="sha512")

        assert len(result) == 128
        assert all(c in "0123456789abcdef" for c in result)

    def test_secure_hash_md5_for_non_security(self) -> None:
        """Secure hash generates MD5 for non-security purposes."""
        result = secure_hash("test data", algorithm="md5")

        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_secure_hash_consistency(self) -> None:
        """Secure hash produces consistent results for same input."""
        data = "consistent test data"

        result1 = secure_hash(data, algorithm="sha256")
        result2 = secure_hash(data, algorithm="sha256")

        assert result1 == result2

    def test_secure_hash_different_for_different_data(self) -> None:
        """Secure hash produces different results for different inputs."""
        result1 = secure_hash("data1", algorithm="sha256")
        result2 = secure_hash("data2", algorithm="sha256")

        assert result1 != result2

    def test_secure_hash_unsupported_algorithm(self) -> None:
        """Secure hash raises ValueError for unsupported algorithms."""
        with pytest.raises(ValueError) as exc_info:
            secure_hash("test", algorithm="unsupported")

        assert "Unsupported algorithm" in str(exc_info.value)

    def test_secure_hash_unicode_handling(self) -> None:
        """Secure hash correctly handles unicode strings."""
        unicode_data = "test ✓ data © 2025"

        result = secure_hash(unicode_data, algorithm="sha256")

        assert len(result) == 64

    def test_secure_hash_empty_input(self) -> None:
        """Secure hash handles empty input."""
        result = secure_hash("", algorithm="sha256")

        assert len(result) == 64
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_secure_hash_large_input(self) -> None:
        """Secure hash handles large inputs efficiently."""
        large_data = "x" * 1_000_000

        result = secure_hash(large_data, algorithm="sha256")

        assert len(result) == 64


class TestSecureSubprocess:
    """Test secure subprocess execution."""

    def test_secure_subprocess_executes_simple_command(self) -> None:
        """Secure subprocess executes simple commands successfully."""
        result = secure_subprocess(["echo", "test"])

        assert result.returncode == 0
        assert "test" in result.stdout

    def test_secure_subprocess_blocks_shell_true(self) -> None:
        """Secure subprocess blocks shell=True for security."""
        with pytest.raises(SecurityError) as exc_info:
            secure_subprocess("echo test", shell=True)

        assert "shell=True is not allowed" in str(exc_info.value)

    def test_secure_subprocess_parses_string_command(self) -> None:
        """Secure subprocess parses string commands into argument lists."""
        result = secure_subprocess("echo test message")

        assert result.returncode == 0
        assert "test" in result.stdout
        assert "message" in result.stdout

    def test_secure_subprocess_accepts_list_command(self) -> None:
        """Secure subprocess accepts command as list."""
        result = secure_subprocess(["echo", "test"])

        assert result.returncode == 0

    def test_secure_subprocess_captures_output(self) -> None:
        """Secure subprocess captures stdout and stderr."""
        result = secure_subprocess(["echo", "output"])

        assert result.stdout is not None
        assert result.stderr is not None
        assert "output" in result.stdout

    def test_secure_subprocess_timeout_enforcement(self) -> None:
        """Secure subprocess enforces timeout."""
        import platform

        if platform.system() == "Windows":
            sleep_cmd = ["timeout", "/t", "10", "/nobreak"]
        else:
            sleep_cmd = ["sleep", "10"]

        with pytest.raises(subprocess.TimeoutExpired):
            secure_subprocess(sleep_cmd, timeout=1)

    def test_secure_subprocess_handles_command_not_found(self) -> None:
        """Secure subprocess handles non-existent commands."""
        with pytest.raises(FileNotFoundError):
            secure_subprocess(["nonexistent_command_12345"])

    def test_secure_subprocess_handles_command_failure(self) -> None:
        """Secure subprocess handles command execution failures."""
        import platform

        if platform.system() == "Windows":
            result = secure_subprocess(["cmd", "/c", "exit 1"])
        else:
            result = secure_subprocess(["sh", "-c", "exit 1"])

        assert result.returncode == 1

    def test_secure_subprocess_with_additional_kwargs(self) -> None:
        """Secure subprocess accepts additional keyword arguments."""
        result = secure_subprocess(
            ["echo", "test"],
            timeout=5,
            check=False
        )

        assert result.returncode == 0


class TestSecureYamlLoad:
    """Test secure YAML loading."""

    def test_secure_yaml_load_parses_dict(self) -> None:
        """Secure YAML load parses dictionary structures."""
        yaml_data = """
        key1: value1
        key2: value2
        nested:
          inner: data
        """

        result = secure_yaml_load(yaml_data)

        assert isinstance(result, dict)
        assert result["key1"] == "value1"
        assert result["key2"] == "value2"
        assert result["nested"]["inner"] == "data"

    def test_secure_yaml_load_parses_list(self) -> None:
        """Secure YAML load parses list structures."""
        yaml_data = """
        - item1
        - item2
        - item3
        """

        result = secure_yaml_load(yaml_data)

        assert isinstance(result, list)
        assert len(result) == 3
        assert "item1" in result

    def test_secure_yaml_load_parses_scalars(self) -> None:
        """Secure YAML load parses scalar values."""
        result = secure_yaml_load("42")
        assert result == 42

        result = secure_yaml_load("true")
        assert result is True

        result = secure_yaml_load("simple string")
        assert result == "simple string"

    def test_secure_yaml_load_handles_empty(self) -> None:
        """Secure YAML load handles empty input."""
        result = secure_yaml_load("")
        assert result is None

    def test_secure_yaml_load_blocks_unsafe_constructs(self) -> None:
        """Secure YAML load blocks unsafe YAML constructs."""
        unsafe_yaml = "!!python/object/apply:os.system ['echo vulnerable']"

        with pytest.raises(yaml.constructor.ConstructorError):
            secure_yaml_load(unsafe_yaml)

    def test_secure_yaml_load_complex_structure(self) -> None:
        """Secure YAML load handles complex nested structures."""
        yaml_data = """
        application:
          name: Intellicrack
          version: 1.0.0
          features:
            - binary_analysis
            - license_cracking
          settings:
            timeout: 300
            threads: 4
        """

        result = secure_yaml_load(yaml_data)

        assert isinstance(result, dict)
        assert result["application"]["name"] == "Intellicrack"
        assert len(result["application"]["features"]) == 2
        assert result["application"]["settings"]["timeout"] == 300


class TestSecureJsonLoad:
    """Test secure JSON loading."""

    def test_secure_json_load_parses_object(self) -> None:
        """Secure JSON load parses JSON objects."""
        json_data = '{"key1": "value1", "key2": 42, "key3": true}'

        result = secure_json_load(json_data)

        assert isinstance(result, dict)
        assert result["key1"] == "value1"
        assert result["key2"] == 42
        assert result["key3"] is True

    def test_secure_json_load_parses_array(self) -> None:
        """Secure JSON load parses JSON arrays."""
        json_data = '["item1", "item2", "item3"]'

        result = secure_json_load(json_data)

        assert isinstance(result, list)
        assert len(result) == 3
        assert result[0] == "item1"

    def test_secure_json_load_parses_nested(self) -> None:
        """Secure JSON load parses nested structures."""
        json_data = '''
        {
            "config": {
                "analysis": {
                    "timeout": 300,
                    "enabled": true
                }
            }
        }
        '''

        result = secure_json_load(json_data)

        assert isinstance(result, dict)
        assert result["config"]["analysis"]["timeout"] == 300
        assert result["config"]["analysis"]["enabled"] is True

    def test_secure_json_load_handles_unicode(self) -> None:
        """Secure JSON load handles unicode characters."""
        json_data = '{"message": "Test ✓ © 2025"}'

        result = secure_json_load(json_data)

        assert isinstance(result, dict)
        assert "✓" in result["message"]
        assert "©" in result["message"]

    def test_secure_json_load_rejects_invalid_json(self) -> None:
        """Secure JSON load raises error for invalid JSON."""
        invalid_json = '{"key": "value",}'

        with pytest.raises(json.JSONDecodeError):
            secure_json_load(invalid_json)

    def test_secure_json_load_empty_object(self) -> None:
        """Secure JSON load handles empty objects."""
        result = secure_json_load('{}')
        assert result == {}

        result = secure_json_load('[]')
        assert result == []


class TestValidateFilePath:
    """Test file path validation."""

    def test_validate_file_path_accepts_valid_path(self) -> None:
        """File path validation accepts valid paths."""
        result = validate_file_path("test.exe")
        assert result is True

        result = validate_file_path("folder/binary.dll")
        assert result is True

    def test_validate_file_path_blocks_path_traversal_dotdot(self) -> None:
        """File path validation blocks .. traversal."""
        with pytest.raises(SecurityError) as exc_info:
            validate_file_path("../etc/passwd")

        assert "malicious path" in str(exc_info.value)

    def test_validate_file_path_blocks_absolute_paths(self) -> None:
        """File path validation blocks absolute paths starting with /."""
        with pytest.raises(SecurityError) as exc_info:
            validate_file_path("/etc/passwd")

        assert "malicious path" in str(exc_info.value)

    def test_validate_file_path_checks_allowed_extensions(self) -> None:
        """File path validation enforces allowed extension list."""
        allowed = [".exe", ".dll", ".sys"]

        result = validate_file_path("program.exe", allowed_extensions=allowed)
        assert result is True

        with pytest.raises(SecurityError) as exc_info:
            validate_file_path("script.py", allowed_extensions=allowed)

        assert "not allowed" in str(exc_info.value)

    def test_validate_file_path_case_insensitive_extensions(self) -> None:
        """File path validation handles extensions case-insensitively."""
        allowed = [".exe", ".dll"]

        result = validate_file_path("program.EXE", allowed_extensions=allowed)
        assert result is True

    def test_validate_file_path_accepts_no_extension_restriction(self) -> None:
        """File path validation allows any extension when not restricted."""
        result = validate_file_path("file.any_extension")
        assert result is True

    def test_validate_file_path_blocks_hidden_traversal(self) -> None:
        """File path validation blocks hidden path traversal."""
        with pytest.raises(SecurityError):
            validate_file_path("safe/../../../etc/passwd")

    def test_validate_file_path_subdirectories_allowed(self) -> None:
        """File path validation allows subdirectories without traversal."""
        result = validate_file_path("subdir/file.exe")
        assert result is True

        result = validate_file_path("deep/nested/path/binary.dll")
        assert result is True


class TestSanitizeInput:
    """Test input sanitization."""

    def test_sanitize_input_removes_null_bytes(self) -> None:
        """Sanitize input removes null bytes."""
        dirty = "test\x00data\x00here"

        result = sanitize_input(dirty)

        assert "\x00" not in result
        assert "test" in result
        assert "data" in result

    def test_sanitize_input_limits_length(self) -> None:
        """Sanitize input enforces maximum length."""
        long_text = "x" * 2000

        result = sanitize_input(long_text, max_length=100)

        assert len(result) == 100

    def test_sanitize_input_removes_control_characters(self) -> None:
        """Sanitize input removes control characters."""
        dirty = "test\x01\x02\x03data\x1F\x7Fhere"

        result = sanitize_input(dirty)

        assert result == "testdatahere"

    def test_sanitize_input_strips_whitespace(self) -> None:
        """Sanitize input strips leading and trailing whitespace."""
        dirty = "   test data   "

        result = sanitize_input(dirty)

        assert result == "test data"

    def test_sanitize_input_preserves_valid_characters(self) -> None:
        """Sanitize input preserves valid characters."""
        clean = "Valid text with numbers 123 and symbols !@#"

        result = sanitize_input(clean)

        assert result == clean

    def test_sanitize_input_handles_unicode(self) -> None:
        """Sanitize input preserves valid unicode characters."""
        unicode_text = "Test ✓ © 2025"

        result = sanitize_input(unicode_text)

        assert "✓" in result
        assert "©" in result

    def test_sanitize_input_empty_string(self) -> None:
        """Sanitize input handles empty strings."""
        result = sanitize_input("")
        assert result == ""

    def test_sanitize_input_only_control_characters(self) -> None:
        """Sanitize input returns empty for input with only control chars."""
        dirty = "\x00\x01\x02\x03\x1F\x7F"

        result = sanitize_input(dirty)

        assert result == ""

    def test_sanitize_input_custom_max_length(self) -> None:
        """Sanitize input respects custom max length."""
        text = "This is a longer text that should be truncated"

        result = sanitize_input(text, max_length=20)

        assert len(result) <= 20

    def test_sanitize_input_combined_cleaning(self) -> None:
        """Sanitize input applies all cleaning operations together."""
        dirty = "  \x00test\x01data\x7Fwith\x00junk  " + ("x" * 2000)

        result = sanitize_input(dirty, max_length=100)

        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x7F" not in result
        assert len(result) <= 100
        assert "test" in result
        assert "data" in result


class TestIntegrationScenarios:
    """Test complete security utility workflows."""

    def test_complete_validation_workflow(self) -> None:
        """Complete workflow using multiple security utilities."""
        user_input = "  test\x00input\x01data  "
        sanitized = sanitize_input(user_input)

        assert "\x00" not in sanitized
        assert sanitized == "testinputdata"

        file_path = "binary.exe"
        validate_file_path(file_path, allowed_extensions=[".exe", ".dll"])

        hash_result = secure_hash(sanitized, algorithm="sha256")
        assert len(hash_result) == 64

    def test_subprocess_with_validation(self) -> None:
        """Subprocess execution with input validation."""
        user_command = "echo test"
        sanitized = sanitize_input(user_command)

        result = secure_subprocess(sanitized)

        assert result.returncode == 0
        assert "test" in result.stdout

    def test_data_loading_and_hashing(self) -> None:
        """Load configuration data and generate hash."""
        json_config = '{"key": "value", "setting": 42}'
        config = secure_json_load(json_config)

        assert isinstance(config, dict)
        assert config["key"] == "value"

        yaml_data = "key: value\nsetting: 42"
        yaml_config = secure_yaml_load(yaml_data)

        assert isinstance(yaml_config, dict)
        assert yaml_config["key"] == "value"

        config_hash = secure_hash(json_config, algorithm="sha256")
        assert len(config_hash) == 64

    def test_multiple_hash_algorithms(self) -> None:
        """Generate hashes with multiple algorithms for same data."""
        data = "test data for hashing"

        sha256_hash = secure_hash(data, algorithm="sha256")
        sha512_hash = secure_hash(data, algorithm="sha512")
        md5_hash = secure_hash(data, algorithm="md5")

        assert len(sha256_hash) == 64
        assert len(sha512_hash) == 128
        assert len(md5_hash) == 32
        assert sha256_hash != md5_hash

    def test_path_validation_with_sanitized_input(self) -> None:
        """Validate paths from sanitized user input."""
        user_path = "  folder/file.exe\x00\x01  "
        sanitized = sanitize_input(user_path)

        validate_file_path(sanitized, allowed_extensions=[".exe", ".dll"])

        hash_result = secure_hash(sanitized, algorithm="sha256")
        assert len(hash_result) == 64
