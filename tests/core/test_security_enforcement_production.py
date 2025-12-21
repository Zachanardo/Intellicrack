"""Production tests for security enforcement module.

Tests validate security policy enforcement including subprocess protection,
pickle serialization control, hashlib algorithm enforcement, and file validation.
"""

import hashlib
import json
import pickle
import subprocess
import tempfile
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.security_enforcement import (
    DateTimeEncoder,
    SecureHash,
    SecurityEnforcement,
    SecurityError,
    get_security_status,
    initialize_security,
    secure_open,
    validate_file_input,
)


@pytest.fixture
def reset_security() -> None:
    """Reset security enforcement state between tests."""
    import intellicrack.core.security_enforcement as se
    se._security = None
    yield
    se._security = None


@pytest.fixture
def security_instance(reset_security: None) -> SecurityEnforcement:
    """Create fresh SecurityEnforcement instance."""
    return SecurityEnforcement()


@pytest.fixture
def security_config_allow_shell() -> dict[str, Any]:
    """Create security config allowing shell=True."""
    return {
        "security": {
            "subprocess": {
                "allow_shell_true": True,
                "shell_whitelist": ["echo", "dir", "ls"],
            },
        },
    }


@pytest.fixture
def security_config_block_md5() -> dict[str, Any]:
    """Create security config blocking MD5."""
    return {
        "security": {
            "hashing": {
                "allow_md5_for_security": False,
                "default_algorithm": "sha256",
            },
        },
    }


class TestDateTimeEncoder:
    """Test custom JSON encoder for datetime and Path objects."""

    def test_encoder_handles_datetime(self) -> None:
        """DateTimeEncoder serializes datetime objects to ISO format."""
        from datetime import datetime

        test_data = {
            "timestamp": datetime(2025, 1, 15, 12, 30, 45),
        }

        result = json.dumps(test_data, cls=DateTimeEncoder)
        assert "2025-01-15T12:30:45" in result

    def test_encoder_handles_date(self) -> None:
        """DateTimeEncoder serializes date objects to ISO format."""
        from datetime import date

        test_data = {
            "date": date(2025, 1, 15),
        }

        result = json.dumps(test_data, cls=DateTimeEncoder)
        assert "2025-01-15" in result

    def test_encoder_handles_path(self) -> None:
        """DateTimeEncoder serializes Path objects to strings."""
        test_data = {
            "path": Path("C:\\test\\file.exe"),
        }

        result = json.dumps(test_data, cls=DateTimeEncoder)
        assert "test" in result
        assert "file.exe" in result

    def test_encoder_handles_mixed_types(self) -> None:
        """DateTimeEncoder handles mixed datetime, date, Path, and regular types."""
        from datetime import datetime, date

        test_data = {
            "timestamp": datetime(2025, 1, 15, 12, 0, 0),
            "date": date(2025, 1, 15),
            "path": Path("D:\\binaries"),
            "string": "test",
            "number": 42,
        }

        result = json.dumps(test_data, cls=DateTimeEncoder)
        parsed = json.loads(result)

        assert "2025-01-15T12:00:00" in parsed["timestamp"]
        assert "2025-01-15" in parsed["date"]
        assert "binaries" in parsed["path"]
        assert parsed["string"] == "test"
        assert parsed["number"] == 42


class TestSecurityEnforcement:
    """Test SecurityEnforcement class initialization and configuration."""

    def test_initialization_loads_config(self, security_instance: SecurityEnforcement) -> None:
        """SecurityEnforcement loads configuration on initialization."""
        assert security_instance.config is not None
        assert security_instance.security_config is not None
        assert isinstance(security_instance.security_config, dict)

    def test_initialization_sets_bypass_to_false(self, security_instance: SecurityEnforcement) -> None:
        """SecurityEnforcement initializes with bypass disabled."""
        assert security_instance._bypass_security is False

    def test_initialization_creates_original_functions_dict(
        self, security_instance: SecurityEnforcement
    ) -> None:
        """SecurityEnforcement creates storage for original functions."""
        assert hasattr(security_instance, "_original_functions")
        assert isinstance(security_instance._original_functions, dict)

    def test_default_config_structure(self, security_instance: SecurityEnforcement) -> None:
        """Default configuration contains all required security sections."""
        default_config = security_instance._get_default_config()

        assert "security" in default_config
        security = default_config["security"]

        assert "sandbox_analysis" in security
        assert "allow_network_access" in security
        assert "hashing" in security
        assert "subprocess" in security
        assert "serialization" in security
        assert "input_validation" in security

    def test_default_config_secure_defaults(self, security_instance: SecurityEnforcement) -> None:
        """Default configuration uses secure settings."""
        default = security_instance._get_default_config()["security"]

        assert default["sandbox_analysis"] is True
        assert default["allow_network_access"] is False
        assert default["hashing"]["allow_md5_for_security"] is False
        assert default["subprocess"]["allow_shell_true"] is False
        assert default["serialization"]["restrict_pickle"] is True

    def test_deep_merge_combines_dicts(self, security_instance: SecurityEnforcement) -> None:
        """Deep merge combines nested dictionaries correctly."""
        base = {
            "level1": {
                "level2": {
                    "existing": "value",
                },
            },
        }

        override = {
            "level1": {
                "level2": {
                    "new": "data",
                },
            },
        }

        security_instance._deep_merge(base, override)

        assert base["level1"]["level2"]["existing"] == "value"
        assert base["level1"]["level2"]["new"] == "data"

    def test_deep_merge_overwrites_values(self, security_instance: SecurityEnforcement) -> None:
        """Deep merge overwrites existing values."""
        base = {"key": "old_value"}
        override = {"key": "new_value"}

        security_instance._deep_merge(base, override)

        assert base["key"] == "new_value"

    def test_enable_bypass_sets_flag(self, security_instance: SecurityEnforcement) -> None:
        """Enable bypass sets bypass flag to True."""
        security_instance.enable_bypass()

        assert security_instance._bypass_security is True

    def test_disable_bypass_clears_flag(self, security_instance: SecurityEnforcement) -> None:
        """Disable bypass sets bypass flag to False."""
        security_instance.enable_bypass()
        security_instance.disable_bypass()

        assert security_instance._bypass_security is False


class TestSubprocessProtection:
    """Test subprocess security enforcement."""

    def test_subprocess_run_blocks_shell_true_by_default(self, reset_security: None) -> None:
        """Subprocess.run with shell=True raises SecurityError when disabled."""
        initialize_security()

        with pytest.raises(SecurityError) as exc_info:
            subprocess.run("echo test", shell=True)

        assert "shell=True is disabled" in str(exc_info.value)

    def test_subprocess_run_allows_shell_false(self, reset_security: None) -> None:
        """Subprocess.run with shell=False executes normally."""
        initialize_security()

        result = subprocess.run(
            ["echo", "test"],
            shell=False,
            capture_output=True
        )

        assert result.returncode == 0

    def test_subprocess_popen_blocks_shell_true(self, reset_security: None) -> None:
        """Subprocess.Popen with shell=True raises SecurityError."""
        initialize_security()

        with pytest.raises(SecurityError):
            subprocess.Popen("echo test", shell=True)

    def test_subprocess_call_blocks_shell_true(self, reset_security: None) -> None:
        """Subprocess.call with shell=True raises SecurityError."""
        initialize_security()

        with pytest.raises(SecurityError):
            subprocess.call("echo test", shell=True)

    def test_subprocess_check_call_blocks_shell_true(self, reset_security: None) -> None:
        """Subprocess.check_call with shell=True raises SecurityError."""
        initialize_security()

        with pytest.raises(SecurityError):
            subprocess.check_call("echo test", shell=True)

    def test_subprocess_check_output_blocks_shell_true(self, reset_security: None) -> None:
        """Subprocess.check_output with shell=True raises SecurityError."""
        initialize_security()

        with pytest.raises(SecurityError):
            subprocess.check_output("echo test", shell=True)

    def test_bypass_allows_shell_true(self, reset_security: None) -> None:
        """Bypass mode allows shell=True subprocess calls."""
        initialize_security()
        import intellicrack.core.security_enforcement as se

        se._security.enable_bypass()

        result = subprocess.run(
            "echo test",
            shell=True,
            capture_output=True
        )

        assert result.returncode == 0


class TestPickleProtection:
    """Test pickle serialization security."""

    def test_pickle_dump_attempts_json_first(self, reset_security: None) -> None:
        """Pickle.dump tries JSON serialization when pickle restricted."""
        initialize_security()

        test_data = {"key": "value", "number": 42}
        buffer = BytesIO()

        pickle.dump(test_data, buffer)

        buffer.seek(0)
        result = json.load(buffer)
        assert result == test_data

    def test_pickle_dumps_attempts_json_first(self, reset_security: None) -> None:
        """Pickle.dumps tries JSON serialization when pickle restricted."""
        initialize_security()

        test_data = {"key": "value"}
        result_bytes = pickle.dumps(test_data)

        result = json.loads(result_bytes.decode("utf-8"))
        assert result == test_data

    def test_pickle_load_attempts_json_first(self, reset_security: None) -> None:
        """Pickle.load tries JSON deserialization when pickle restricted."""
        initialize_security()

        test_data = {"key": "value"}
        buffer = BytesIO()
        json.dump(test_data, buffer)
        buffer.seek(0)

        result = pickle.load(buffer)
        assert result == test_data

    def test_pickle_loads_attempts_json_first(self, reset_security: None) -> None:
        """Pickle.loads tries JSON deserialization when pickle restricted."""
        initialize_security()

        test_data = {"key": "value"}
        json_bytes = json.dumps(test_data).encode("utf-8")

        result = pickle.loads(json_bytes)
        assert result == test_data

    def test_pickle_fallback_for_non_json_serializable(self, reset_security: None) -> None:
        """Pickle falls back to pickle for non-JSON-serializable objects."""
        initialize_security()
        import intellicrack.core.security_enforcement as se
        se._security.enable_bypass()

        class CustomClass:
            def __init__(self, value: int) -> None:
                self.value = value

        test_obj = CustomClass(42)
        buffer = BytesIO()

        pickle.dump(test_obj, buffer)
        buffer.seek(0)
        result = pickle.load(buffer)

        assert result.value == 42


class TestHashlibProtection:
    """Test hashlib algorithm enforcement."""

    def test_hashlib_md5_blocked_by_default(self, reset_security: None) -> None:
        """Hashlib.md5() is substituted with sha256 when blocked."""
        initialize_security()

        hash_obj = hashlib.md5(b"test data")

        assert hash_obj.name == "sha256"

    def test_hashlib_new_md5_blocked(self, reset_security: None) -> None:
        """Hashlib.new('md5') is substituted with sha256 when blocked."""
        initialize_security()

        hash_obj = hashlib.new("md5", b"test data")

        assert hash_obj.name == "sha256"

    def test_hashlib_sha256_allowed(self, reset_security: None) -> None:
        """Hashlib.sha256() works normally."""
        initialize_security()

        hash_obj = hashlib.sha256(b"test data")

        assert hash_obj.name == "sha256"

    def test_secure_hash_blocks_md5_by_default(self, reset_security: None) -> None:
        """SecureHash blocks MD5 and uses default algorithm."""
        initialize_security()

        hash_obj = SecureHash("md5", b"test")

        assert hash_obj.name == "sha256"

    def test_secure_hash_allows_sha256(self, reset_security: None) -> None:
        """SecureHash allows sha256."""
        initialize_security()

        hash_obj = SecureHash("sha256", b"test")

        assert hash_obj.name == "sha256"

    def test_secure_hash_update(self, reset_security: None) -> None:
        """SecureHash update method works correctly."""
        initialize_security()

        hash_obj = SecureHash("sha256", b"test")
        hash_obj.update(b" data")

        digest = hash_obj.hexdigest()
        assert len(digest) == 64

    def test_secure_hash_digest_methods(self, reset_security: None) -> None:
        """SecureHash provides both binary and hex digests."""
        initialize_security()

        hash_obj = SecureHash("sha256", b"test")

        binary_digest = hash_obj.digest()
        hex_digest = hash_obj.hexdigest()

        assert len(binary_digest) == 32
        assert len(hex_digest) == 64
        assert hex_digest == binary_digest.hex()

    def test_secure_hash_copy(self, reset_security: None) -> None:
        """SecureHash copy creates independent hash object."""
        initialize_security()

        hash_obj1 = SecureHash("sha256", b"test")
        hash_obj2 = hash_obj1.copy()

        hash_obj2.update(b" data")

        assert hash_obj1.hexdigest() != hash_obj2.hexdigest()

    def test_secure_hash_properties(self, reset_security: None) -> None:
        """SecureHash exposes digest_size and block_size properties."""
        initialize_security()

        hash_obj = SecureHash("sha256")

        assert hash_obj.digest_size == 32
        assert hash_obj.block_size == 64


class TestFileValidation:
    """Test file input validation."""

    def test_validate_file_input_passes_for_valid_file(self, tmp_path: Path) -> None:
        """File validation passes for valid files."""
        initialize_security()

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        result = validate_file_input(test_file, "read")
        assert result is True

    def test_validate_file_input_blocks_path_traversal(self, tmp_path: Path) -> None:
        """File validation blocks path traversal attempts in strict mode."""
        initialize_security()

        malicious_path = tmp_path / ".." / "etc" / "passwd"

        with pytest.raises(SecurityError) as exc_info:
            validate_file_input(malicious_path, "read")

        assert "Path traversal" in str(exc_info.value)

    def test_validate_file_input_checks_max_size(self, tmp_path: Path, reset_security: None) -> None:
        """File validation enforces maximum file size."""
        import intellicrack.core.security_enforcement as se
        se._security = SecurityEnforcement()
        se._security.security_config["input_validation"]["max_file_size"] = 100

        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"x" * 200)

        with pytest.raises(SecurityError) as exc_info:
            validate_file_input(large_file, "read")

        assert "exceeds maximum size" in str(exc_info.value)

    def test_validate_file_input_checks_extensions(self, tmp_path: Path, reset_security: None) -> None:
        """File validation enforces allowed extensions."""
        import intellicrack.core.security_enforcement as se
        se._security = SecurityEnforcement()
        se._security.security_config["input_validation"]["allowed_extensions"] = [".txt", ".exe"]

        invalid_file = tmp_path / "malicious.dll"

        with pytest.raises(SecurityError) as exc_info:
            validate_file_input(invalid_file, "read")

        assert "not allowed" in str(exc_info.value)

    def test_validate_file_input_allows_valid_extension(self, tmp_path: Path, reset_security: None) -> None:
        """File validation allows files with permitted extensions."""
        import intellicrack.core.security_enforcement as se
        se._security = SecurityEnforcement()
        se._security.security_config["input_validation"]["allowed_extensions"] = [".txt", ".exe"]

        valid_file = tmp_path / "binary.exe"
        valid_file.write_bytes(b"MZ")

        result = validate_file_input(valid_file, "read")
        assert result is True

    def test_validate_file_input_bypasses_when_disabled(self, tmp_path: Path, reset_security: None) -> None:
        """File validation is bypassed when security bypass enabled."""
        initialize_security()
        import intellicrack.core.security_enforcement as se

        se._security.enable_bypass()

        malicious_path = tmp_path / ".." / "etc" / "passwd"
        result = validate_file_input(malicious_path, "read")

        assert result is True


class TestSecureOpen:
    """Test secure file opening."""

    def test_secure_open_validates_read_mode(self, tmp_path: Path) -> None:
        """Secure open validates files in read mode."""
        initialize_security()

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        with secure_open(test_file, "r") as f:
            content = f.read()

        assert content == "content"

    def test_secure_open_validates_write_mode(self, tmp_path: Path) -> None:
        """Secure open validates files in write mode."""
        initialize_security()

        test_file = tmp_path / "output.txt"

        with secure_open(test_file, "w") as f:
            f.write("test data")

        assert test_file.read_text() == "test data"

    def test_secure_open_blocks_invalid_paths(self, tmp_path: Path) -> None:
        """Secure open blocks path traversal attempts."""
        initialize_security()

        malicious_path = tmp_path / ".." / "etc" / "passwd"

        with pytest.raises(SecurityError):
            secure_open(malicious_path, "r")


class TestSecurityInitialization:
    """Test security system initialization."""

    def test_initialize_security_creates_global_instance(self, reset_security: None) -> None:
        """Initialize security creates global _security instance."""
        import intellicrack.core.security_enforcement as se

        initialize_security()

        assert se._security is not None
        assert isinstance(se._security, SecurityEnforcement)

    def test_initialize_security_patches_subprocess(self, reset_security: None) -> None:
        """Initialize security applies subprocess patches."""
        initialize_security()
        status = get_security_status()

        assert status["patches_applied"]["subprocess"] is True

    def test_initialize_security_patches_pickle(self, reset_security: None) -> None:
        """Initialize security applies pickle patches."""
        initialize_security()
        status = get_security_status()

        assert status["patches_applied"]["pickle"] is True

    def test_initialize_security_patches_hashlib(self, reset_security: None) -> None:
        """Initialize security applies hashlib patches."""
        initialize_security()
        status = get_security_status()

        assert status["patches_applied"]["hashlib"] is True


class TestSecurityStatus:
    """Test security status reporting."""

    def test_get_security_status_uninitialized(self, reset_security: None) -> None:
        """Security status reports uninitialized state."""
        status = get_security_status()

        assert status["initialized"] is False
        assert status["bypass_enabled"] is False

    def test_get_security_status_initialized(self, reset_security: None) -> None:
        """Security status reports initialized state."""
        initialize_security()
        status = get_security_status()

        assert status["initialized"] is True
        assert "config" in status
        assert "patches_applied" in status

    def test_get_security_status_bypass_enabled(self, reset_security: None) -> None:
        """Security status reports bypass state."""
        initialize_security()
        import intellicrack.core.security_enforcement as se

        se._security.enable_bypass()
        status = get_security_status()

        assert status["bypass_enabled"] is True


class TestIntegrationScenarios:
    """Test complete security enforcement scenarios."""

    def test_complete_security_workflow(self, reset_security: None, tmp_path: Path) -> None:
        """Complete workflow with security initialization and validation."""
        initialize_security()

        test_file = tmp_path / "secure_data.txt"
        test_file.write_text("sensitive data")

        with secure_open(test_file, "r") as f:
            content = f.read()

        assert content == "sensitive data"

        hash_obj = SecureHash("sha256", b"test")
        assert len(hash_obj.hexdigest()) == 64

        with pytest.raises(SecurityError):
            subprocess.run("malicious command", shell=True)

    def test_bypass_mode_workflow(self, reset_security: None) -> None:
        """Bypass mode allows all restricted operations."""
        initialize_security()
        import intellicrack.core.security_enforcement as se

        se._security.enable_bypass()

        result = subprocess.run("echo test", shell=True, capture_output=True)
        assert result.returncode == 0

        md5_hash = hashlib.md5(b"data")
        assert md5_hash.name == "md5"

        se._security.disable_bypass()

        with pytest.raises(SecurityError):
            subprocess.run("echo test", shell=True)

    def test_mixed_operations_enforce_policy(self, reset_security: None, tmp_path: Path) -> None:
        """Mixed operations all respect security policy."""
        initialize_security()

        test_data = {"key": "value"}
        buffer = BytesIO()
        pickle.dump(test_data, buffer)
        buffer.seek(0)
        loaded = pickle.load(buffer)
        assert loaded == test_data

        hash_obj = hashlib.md5(b"test")
        assert hash_obj.name == "sha256"

        with pytest.raises(SecurityError):
            subprocess.run("echo test", shell=True)
