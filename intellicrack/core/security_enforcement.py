"""Security Enforcement Module for Intellicrack.

Implements security policies defined in intellicrack_config.json.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pickle  # noqa: S403
import subprocess
from datetime import date, datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from intellicrack.utils.type_safety import validate_type

from ..utils.logger import log_all_methods, log_function_call


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class DateTimeEncoder(json.JSONEncoder):
    """Customize JSON encoder for datetime and date objects."""

    def default(self, obj: datetime | date | Path | object) -> str:
        """Convert datetime, date, and Path objects to JSON-serializable strings.

        Args:
            obj: Object to serialize.

        Returns:
            JSON-serializable string representation of the object.

        """
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return str(obj) if isinstance(obj, Path) else super().default(obj)


@log_all_methods
class SecurityEnforcement:
    """Central security enforcement class."""

    _original_functions: dict[str, Callable[..., Any]]
    _bypass_security: bool
    config: dict[str, Any]
    security_config: dict[str, Any]

    def __init__(self) -> None:
        """Initialize security enforcement with configuration and tracking state."""
        logger.info("SecurityEnforcement: Initializing security enforcement module.")
        self.config = self._load_config()
        self.security_config = self.config.get("security", {})
        self._original_functions = {}
        self._bypass_security = False
        logger.debug("SecurityEnforcement: Initial security configuration loaded: %s", self.security_config)
        logger.info("SecurityEnforcement: Initialization complete.")

    def _load_config(self) -> dict[str, Any]:
        """Load security configuration from main IntellicrackConfig.

        Returns:
            Security configuration dictionary with merged defaults if needed.

        """
        logger.debug("SecurityEnforcement: Attempting to load security configuration from IntellicrackConfig.")
        try:
            from intellicrack.core.config_manager import IntellicrackConfig

            config_manager_instance = IntellicrackConfig()
            config_data: dict[str, Any] = config_manager_instance._config if hasattr(config_manager_instance, "_config") else {}
            logger.debug("SecurityEnforcement: IntellicrackConfig loaded. Config data keys: %s", list(config_data.keys()))

            if "security" not in config_data:
                logger.info("SecurityEnforcement: 'security' section not found in main config. Merging with default security settings.")
                default_security_config = self._get_default_config()
                if "security" not in config_data:
                    config_data["security"] = {}
                self._deep_merge(config_data["security"], default_security_config["security"])

                try:
                    config_manager_instance.set("security", config_data["security"], save=True)
                    logger.info("SecurityEnforcement: Updated main config saved with default security settings.")
                except Exception as save_e:
                    logger.warning(
                        "SecurityEnforcement: Failed to save updated config with default security settings: %s", save_e, exc_info=True
                    )
            else:
                logger.debug("SecurityEnforcement: 'security' section found in main config.")

            logger.debug("SecurityEnforcement: Final security configuration loaded: %s", config_data.get("security"))
            return config_data
        except Exception as e:
            logger.exception(
                "SecurityEnforcement: Failed to load config from IntellicrackConfig: %s",
                e,
            )
            logger.warning("SecurityEnforcement: Using default security settings due to configuration load failure.")
            return self._get_default_config()

    def _get_default_config(self) -> dict[str, Any]:
        """Return default security configuration.

        Returns:
            Default security configuration dictionary with standard policies.

        """
        logger.debug("SecurityEnforcement: Providing default security configuration.")
        return {
            "security": {
                "sandbox_analysis": True,
                "allow_network_access": False,
                "log_sensitive_data": False,
                "encrypt_config": False,
                "hashing": {
                    "default_algorithm": "sha256",
                    "allow_md5_for_security": False,
                },
                "subprocess": {
                    "allow_shell_true": False,
                    "shell_whitelist": [],
                },
                "serialization": {
                    "default_format": "json",
                    "restrict_pickle": True,
                },
                "input_validation": {
                    "strict_mode": True,
                    "max_file_size": False,
                    "allowed_extensions": False,
                },
            },
        }

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> None:
        """Deep merge override dict into base dict.

        Args:
            base: Dictionary to merge into (modified in-place).
            override: Dictionary containing values to merge into base.

        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def enable_bypass(self) -> None:
        """Enable security bypass for critical operations."""
        self._bypass_security = True
        logger.warning("SecurityEnforcement: !!! SECURITY BYPASS ENABLED - USE WITH EXTREME CAUTION !!!")
        logger.debug("SecurityEnforcement: Security bypass flag set to True.")

    def disable_bypass(self) -> None:
        """Disable security bypass."""
        self._bypass_security = False
        logger.info("SecurityEnforcement: Security bypass disabled.")
        logger.debug("SecurityEnforcement: Security bypass flag set to False.")


_security: SecurityEnforcement | None = None


def _get_security() -> SecurityEnforcement:
    """Get the global security instance, initializing if needed.

    Returns:
        The SecurityEnforcement instance.

    Raises:
        RuntimeError: If security initialization fails unexpectedly.

    """
    global _security
    if _security is None:
        _security = SecurityEnforcement()
    return _security


@log_function_call
def _secure_subprocess_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    """Secure wrapper for subprocess.run.

    Validates subprocess.run calls against security policy, enforcing shell
    restrictions and command whitelisting.

    Args:
        *args: Positional arguments passed to subprocess.run.
        **kwargs: Keyword arguments passed to subprocess.run.

    Returns:
        Result of subprocess.run call.

    Raises:
        SecurityError: If shell=True is used when disabled by policy or command
            is not in whitelist.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for subprocess.run.")
        return validate_type(sec._original_functions["subprocess.run"](*args, **kwargs), subprocess.CompletedProcess)

    shell = kwargs.get("shell", False)
    if shell and not sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.run with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning("Blocked subprocess.run with shell=True: %s", args)
        raise SecurityError(error_msg)

    logger.debug("subprocess.run: %s", args)

    if shell:
        whitelist: list[str] = sec.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd) if hasattr(cmd, "__iter__") else str(cmd)

        if whitelist and all(allowed not in cmd_str for allowed in whitelist):
            logger.warning("Command not in whitelist: %s", cmd_str)
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        if whitelist:
            logger.debug("Command '%s' is in shell whitelist.", cmd_str)

    return validate_type(sec._original_functions["subprocess.run"](*args, **kwargs), subprocess.CompletedProcess)


@log_function_call
def _secure_subprocess_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[Any]:
    """Secure wrapper for subprocess.Popen.

    Validates subprocess.Popen calls against security policy, enforcing shell
    restrictions and command whitelisting.

    Args:
        *args: Positional arguments passed to subprocess.Popen.
        **kwargs: Keyword arguments passed to subprocess.Popen.

    Returns:
        Result of subprocess.Popen call.

    Raises:
        SecurityError: If shell=True is used when disabled by policy or command
            is not in whitelist.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for subprocess.Popen.")
        return validate_type(sec._original_functions["subprocess.Popen"](*args, **kwargs), subprocess.Popen)

    shell = kwargs.get("shell", False)
    if shell and not sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.Popen with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning("Blocked subprocess.Popen with shell=True: %s", args)
        raise SecurityError(error_msg)

    logger.debug("subprocess.Popen: %s", args)

    if shell:
        whitelist: list[str] = sec.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd) if hasattr(cmd, "__iter__") else str(cmd)

        if whitelist and all(allowed not in cmd_str for allowed in whitelist):
            logger.warning("Command not in whitelist: %s", cmd_str)
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        if whitelist:
            logger.debug("Command '%s' is in shell whitelist.", cmd_str)

    return validate_type(sec._original_functions["subprocess.Popen"](*args, **kwargs), subprocess.Popen)


@log_function_call
def _secure_subprocess_call(*args: Any, **kwargs: Any) -> int:
    """Secure wrapper for subprocess.call.

    Validates subprocess.call calls against security policy, enforcing shell
    restrictions.

    Args:
        *args: Positional arguments passed to subprocess.call.
        **kwargs: Keyword arguments passed to subprocess.call.

    Returns:
        Result of subprocess.call call.

    Raises:
        SecurityError: If shell=True is used when disabled by policy.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for subprocess.call.")
        return validate_type(sec._original_functions["subprocess.call"](*args, **kwargs), int)

    shell = kwargs.get("shell", False)
    if shell and not sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.call with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning("Blocked subprocess.call with shell=True: %s", args)
        raise SecurityError(error_msg)

    logger.debug("subprocess.call: %s", args)
    return validate_type(sec._original_functions["subprocess.call"](*args, **kwargs), int)


@log_function_call
def _secure_subprocess_check_call(*args: Any, **kwargs: Any) -> int:
    """Secure wrapper for subprocess.check_call.

    Validates subprocess.check_call calls against security policy, enforcing
    shell restrictions.

    Args:
        *args: Positional arguments passed to subprocess.check_call.
        **kwargs: Keyword arguments passed to subprocess.check_call.

    Returns:
        Result of subprocess.check_call call.

    Raises:
        SecurityError: If shell=True is used when disabled by policy.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for subprocess.check_call.")
        return validate_type(sec._original_functions["subprocess.check_call"](*args, **kwargs), int)

    shell = kwargs.get("shell", False)
    if shell and not sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.check_call with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning("Blocked subprocess.check_call with shell=True: %s", args)
        raise SecurityError(error_msg)

    logger.debug("subprocess.check_call: %s", args)
    return validate_type(sec._original_functions["subprocess.check_call"](*args, **kwargs), int)


@log_function_call
def _secure_subprocess_check_output(*args: Any, **kwargs: Any) -> bytes:
    """Secure wrapper for subprocess.check_output.

    Validates subprocess.check_output calls against security policy, enforcing
    shell restrictions.

    Args:
        *args: Positional arguments passed to subprocess.check_output.
        **kwargs: Keyword arguments passed to subprocess.check_output.

    Returns:
        Result of subprocess.check_output call.

    Raises:
        SecurityError: If shell=True is used when disabled by policy.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for subprocess.check_output.")
        return validate_type(sec._original_functions["subprocess.check_output"](*args, **kwargs), bytes)

    shell = kwargs.get("shell", False)
    if shell and not sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.check_output with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning("Blocked subprocess.check_output with shell=True: %s", args)
        raise SecurityError(error_msg)

    logger.debug("subprocess.check_output: %s", args)
    return validate_type(sec._original_functions["subprocess.check_output"](*args, **kwargs), bytes)


@log_function_call
def _secure_pickle_dump(
    obj: object,
    file: IO[bytes],
    protocol: int | None = None,
    *,
    fix_imports: bool = True,
    buffer_callback: Callable[[pickle.PickleBuffer], object] | None = None,
) -> None:
    """Secure wrapper for pickle.dump.

    Attempts to serialize using JSON first when pickle restriction is enabled,
    falling back to pickle if JSON serialization fails.

    Args:
        obj: Object to serialize.
        file: File-like object to write to.
        protocol: Pickle protocol version (optional).
        fix_imports: Whether to fix imports for Python 2/3 compatibility.
        buffer_callback: Optional callback for buffer protocol objects.

    Raises:
        TypeError: If object cannot be serialized to either JSON or pickle.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for pickle.dump.")
        sec._original_functions["pickle.dump"](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)
        return

    if sec.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle dump attempted with restrict_pickle=True, consider using JSON")
        logger.debug("Attempting JSON serialization instead of pickle.")
        try:
            if hasattr(file, "write"):
                json_file: Any = file
                json.dump(obj, json_file, cls=DateTimeEncoder)
                logger.info("Successfully serialized to JSON instead of pickle")
                logger.debug("JSON serialization successful for pickle.dump.")
                return
            raise TypeError("File object required for JSON dump")
        except (TypeError, ValueError) as e:
            logger.warning("JSON serialization failed, falling back to pickle: %s", e, exc_info=True)
            logger.debug("JSON serialization failed for pickle.dump: %s. Falling back to original pickle.dump.", e)

    logger.debug("pickle.dump: object type=%s", type(obj).__name__)
    sec._original_functions["pickle.dump"](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)


@log_function_call
def _secure_pickle_dumps(
    obj: object,
    protocol: int | None = None,
    *,
    fix_imports: bool = True,
    buffer_callback: Callable[[pickle.PickleBuffer], object] | None = None,
) -> bytes:
    """Secure wrapper for pickle.dumps.

    Attempts to serialize using JSON first when pickle restriction is enabled,
    falling back to pickle if JSON serialization fails.

    Args:
        obj: Object to serialize.
        protocol: Pickle protocol version (optional).
        fix_imports: Whether to fix imports for Python 2/3 compatibility.
        buffer_callback: Optional callback for buffer protocol objects.

    Returns:
        Serialized object as bytes.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for pickle.dumps.")
        return validate_type(
            sec._original_functions["pickle.dumps"](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback), bytes
        )

    if sec.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle dumps attempted with restrict_pickle=True, consider using JSON")
        logger.debug("Attempting JSON serialization instead of pickle.")
        try:
            result = json.dumps(obj, cls=DateTimeEncoder)
            logger.info("Successfully serialized to JSON instead of pickle")
            logger.debug("JSON serialization successful for pickle.dumps.")
            return result.encode("utf-8")
        except (TypeError, ValueError) as e:
            logger.warning("JSON serialization failed, falling back to pickle: %s", e, exc_info=True)
            logger.debug("JSON serialization failed for pickle.dumps: %s. Falling back to original pickle.dumps.", e)

    logger.debug("pickle.dumps: object type=%s", type(obj).__name__)
    return validate_type(
        sec._original_functions["pickle.dumps"](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback), bytes
    )


@log_function_call
def _secure_pickle_load(
    file: IO[bytes],
    *,
    fix_imports: bool = True,
    encoding: str = "ASCII",
    errors: str = "strict",
    buffers: Iterable[Any] | None = None,
) -> Any:
    """Secure wrapper for pickle.load.

    Attempts to deserialize using JSON first when pickle restriction is enabled,
    falling back to pickle if JSON deserialization fails.

    Args:
        file: File-like object to read from.
        fix_imports: Whether to fix imports for Python 2/3 compatibility.
        encoding: Text encoding for deserialization.
        errors: How to handle encoding errors.
        buffers: Optional buffer protocol objects.

    Returns:
        Deserialized object.

    Raises:
        TypeError: If object cannot be deserialized from either JSON or pickle.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for pickle.load.")
        return sec._original_functions["pickle.load"](
            file,
            fix_imports=fix_imports,
            encoding=encoding,
            errors=errors,
            buffers=buffers,
        )

    if sec.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle load attempted with restrict_pickle=True, attempting JSON first")
        logger.debug("Attempting JSON deserialization instead of pickle.")
        try:
            if hasattr(file, "read") and hasattr(file, "seek"):
                file.seek(0)
                json_file: Any = file
                result = json.load(json_file)
                logger.debug("JSON deserialization successful for pickle.load.")
                return result
            raise TypeError("File object required for JSON load")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning("JSON deserialization failed, falling back to pickle: %s", e, exc_info=True)
            logger.debug("JSON deserialization failed for pickle.load: %s. Falling back to original pickle.load.", e)
            if hasattr(file, "seek"):
                file.seek(0)

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.load.")
    return sec._original_functions["pickle.load"](file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)


@log_function_call
def _secure_pickle_loads(
    data: bytes,
    *,
    fix_imports: bool = True,
    encoding: str = "ASCII",
    errors: str = "strict",
    buffers: Iterable[Any] | None = None,
) -> Any:
    """Secure wrapper for pickle.loads.

    Attempts to deserialize using JSON first when pickle restriction is enabled,
    falling back to pickle if JSON deserialization fails.

    Args:
        data: Bytes to deserialize.
        fix_imports: Whether to fix imports for Python 2/3 compatibility.
        encoding: Text encoding for deserialization.
        errors: How to handle encoding errors.
        buffers: Optional buffer protocol objects.

    Returns:
        Deserialized object.

    """
    sec = _get_security()
    if sec._bypass_security:
        logger.debug("Security bypass active for pickle.loads.")
        return sec._original_functions["pickle.loads"](
            data,
            fix_imports=fix_imports,
            encoding=encoding,
            errors=errors,
            buffers=buffers,
        )

    if sec.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle loads attempted with restrict_pickle=True, attempting JSON first")
        logger.debug("Attempting JSON deserialization instead of pickle.")
        try:
            data_str = data.decode("utf-8")
            result = json.loads(data_str)
            logger.debug("JSON deserialization successful for pickle.loads.")
            return result
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("JSON deserialization failed, falling back to pickle: %s", e, exc_info=True)
            logger.debug("JSON deserialization failed for pickle.loads: %s. Falling back to original pickle.loads.", e)

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.loads.")
    return sec._original_functions["pickle.loads"](data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)


class SecureHash:
    """Secure hash wrapper that enforces algorithm policies."""

    _hash: Any
    _name: str

    def __init__(self, name: str, data: bytes = b"") -> None:
        """Initialize secure hash with algorithm policy enforcement.

        Args:
            name: Hash algorithm name (e.g., 'sha256', 'md5').
            data: Initial data to hash (optional).

        """
        sec = _get_security()
        self._name = name
        allow_md5 = sec.security_config.get("hashing", {}).get("allow_md5_for_security", False)

        if name.lower() in {"md5"} and not allow_md5 and not sec._bypass_security:
            logger.warning("MD5 hash requested but not allowed for security purposes")
            default_algo: str = sec.security_config.get("hashing", {}).get("default_algorithm", "sha256")
            logger.info("Using %s instead of MD5", default_algo)
            name = default_algo
            logger.debug("MD5 blocked. Using default algorithm: %s", name)

        self._hash = getattr(hashlib, name)(data)

    def update(self, data: bytes) -> None:
        """Update hash with additional data.

        Args:
            data: Bytes to add to hash calculation.

        Returns:
            None.

        """
        self._hash.update(data)

    def digest(self) -> bytes:
        """Get binary digest of hashed data.

        Returns:
            Binary digest.

        """
        result: bytes = self._hash.digest()
        return result

    def hexdigest(self) -> str:
        """Get hexadecimal digest of hashed data.

        Returns:
            Hexadecimal string digest.

        """
        result: str = self._hash.hexdigest()
        return result

    def copy(self) -> SecureHash:
        """Create a copy of this hash object.

        Returns:
            New SecureHash instance with copied state.

        """
        new_hash = SecureHash.__new__(SecureHash)
        new_hash._name = self._name
        new_hash._hash = self._hash.copy()
        return new_hash

    @property
    def digest_size(self) -> int:
        """Get size of digest in bytes.

        Returns:
            Digest size.

        """
        result: int = self._hash.digest_size
        return result

    @property
    def block_size(self) -> int:
        """Get internal block size of hash algorithm.

        Returns:
            Block size in bytes.

        """
        result: int = self._hash.block_size
        return result

    @property
    def name(self) -> str:
        """Get hash algorithm name.

        Returns:
            Algorithm name.

        """
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        """Set hash algorithm name.

        Args:
            value: Algorithm name.

        """
        self._name = value


@log_function_call
def _secure_hashlib_new(name: str, data: bytes = b"", **kwargs: Any) -> Any:
    """Secure wrapper for hashlib.new.

    Creates hash objects with algorithm policy enforcement, blocking MD5 unless
    explicitly allowed by security configuration.

    Args:
        name: Hash algorithm name.
        data: Initial data to hash (optional).
        **kwargs: Additional arguments passed to hashlib.new.

    Returns:
        Hash object.

    """
    sec = _get_security()
    if sec._bypass_security:
        return sec._original_functions["hashlib.new"](name, data, **kwargs)

    allow_md5 = sec.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if name.lower() in {"md5"} and not allow_md5:
        logger.warning("hashlib.new('%s') requested but not allowed for security", name)
        default_algo: str = sec.security_config.get("hashing", {}).get("default_algorithm", "sha256")
        logger.info("Using %s instead", default_algo)
        name = default_algo
        logger.debug("MD5 blocked. Using default algorithm: %s", name)

    logger.debug("hashlib.new: algorithm=%s", name)
    return sec._original_functions["hashlib.new"](name, data, **kwargs)


@log_function_call
def _secure_hashlib_md5(data: bytes = b"", **kwargs: Any) -> Any:
    """Secure wrapper for hashlib.md5.

    Blocks MD5 hashing unless explicitly allowed by security configuration,
    substituting the configured default algorithm instead.

    Args:
        data: Initial data to hash (optional).
        **kwargs: Additional arguments passed to hashlib.md5.

    Returns:
        Hash object.

    """
    sec = _get_security()
    if sec._bypass_security:
        return sec._original_functions["hashlib.md5"](data, **kwargs)

    allow_md5 = sec.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if not allow_md5:
        logger.warning("hashlib.md5() requested but not allowed for security")
        default_algo: str = sec.security_config.get("hashing", {}).get("default_algorithm", "sha256")
        logger.info("Using %s instead", default_algo)
        logger.debug("MD5 blocked. Using default algorithm: %s", default_algo)
        return getattr(hashlib, default_algo)(data, **kwargs)

    logger.debug("hashlib.md5: allowed by configuration")
    return sec._original_functions["hashlib.md5"](data, **kwargs)


@log_function_call
def validate_file_input(file_path: str | Path, operation: str = "read") -> bool:
    """Validate file input based on security configuration.

    Performs security validation on file paths including size checks, extension
    whitelisting, and path traversal detection.

    Args:
        file_path: Path to file to validate.
        operation: Type of operation ('read' or 'write').

    Returns:
        True if validation passes.

    Raises:
        SecurityError: If any validation check fails.

    """
    sec = _get_security()
    logger.debug("Validating file input for operation '%s': %s", operation, file_path)
    if sec._bypass_security:
        logger.debug("Security bypass active for file input validation.")
        return True

    path_obj = Path(file_path)
    validation_config: dict[str, Any] = sec.security_config.get("input_validation", {})

    if not validation_config.get("strict_mode", True):
        logger.debug("Strict mode disabled. Skipping file input validation.")
        return True

    max_size = validation_config.get("max_file_size", False)
    if max_size and isinstance(max_size, (int, float)):
        logger.debug("Checking file size against max_size: %s", max_size)
        try:
            file_size = path_obj.stat().st_size
            if file_size > max_size:
                error_msg = "File %s exceeds max size: %s > %s"
                logger.error(error_msg, path_obj, file_size, max_size)
                logger.warning(error_msg, path_obj, file_size, max_size)
                raise SecurityError(f"File exceeds maximum size limit: {file_size} > {max_size}")
            logger.debug("File size %s is within limits.", file_size)
        except OSError:
            logger.debug("File does not exist yet, skipping size check.", exc_info=True)

    allowed_extensions = validation_config.get("allowed_extensions", False)
    if allowed_extensions and isinstance(allowed_extensions, list):
        logger.debug("Checking file extension against allowed_extensions: %s", allowed_extensions)
        file_ext = path_obj.suffix.lower()
        if file_ext not in allowed_extensions:
            error_msg = "File extension %s not in allowed list: %s"
            logger.error(error_msg, file_ext, allowed_extensions)
            logger.warning(error_msg, file_ext, allowed_extensions)
            raise SecurityError(f"File extension {file_ext} not allowed")
        logger.debug("File extension '%s' is allowed.", file_ext)

    try:
        logger.debug("Checking for path traversal.")
        path_obj.resolve()
        if ".." in str(path_obj):
            logger.warning("Potential path traversal detected: %s", path_obj)
            if validation_config.get("strict_mode", True):
                error_msg = "Path traversal not allowed in strict mode"
                logger.error(error_msg)
                raise SecurityError(error_msg)
        logger.debug("Path traversal check passed for %s.", path_obj)
    except SecurityError:
        raise
    except Exception as e:
        logger.debug("Security validation exception during path traversal check: %s", e, exc_info=True)

    logger.debug("File validation passed for %s: %s", operation, path_obj)
    return True


@log_function_call
def secure_open(
    file: str | Path,
    mode: str = "r",
    buffering: int = -1,
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
    closefd: bool = True,
    opener: Callable[[str, int], int] | None = None,
) -> IO[Any]:
    """Secure wrapper for open() with validation.

    Opens files with security validation to enforce access policies.

    Args:
        file: Path to file to open.
        mode: File open mode (e.g., 'r', 'w', 'a').
        buffering: Buffering policy.
        encoding: Text encoding.
        errors: How to handle encoding errors.
        newline: Newline handling.
        closefd: Whether to close the file descriptor.
        opener: Custom opener function.

    Returns:
        File object.

    """
    logger.debug("Attempting to securely open file: %s with mode: %s", file, mode)
    if "r" in mode or "a" in mode:
        validate_file_input(file, "read")
    if "w" in mode or "a" in mode:
        validate_file_input(file, "write")
    logger.debug("File %s validated. Proceeding with open().", file)
    return open(
        file,
        mode,
        buffering=buffering,
        encoding=encoding,
        errors=errors,
        newline=newline,
        closefd=closefd,
        opener=opener,
    )


def _monkey_patch_subprocess() -> None:
    """Apply subprocess security patches.

    Replaces subprocess module functions with secure wrappers that enforce
    shell command restrictions and whitelist validation based on security
    configuration.

    """
    sec = _get_security()
    logger.debug("Applying subprocess security patches.")
    if "subprocess.run" not in sec._original_functions:
        logger.debug("Storing original subprocess functions.")
        sec._original_functions["subprocess.run"] = subprocess.run
        sec._original_functions["subprocess.Popen"] = subprocess.Popen
        sec._original_functions["subprocess.call"] = subprocess.call
        sec._original_functions["subprocess.check_call"] = subprocess.check_call
        sec._original_functions["subprocess.check_output"] = subprocess.check_output
    else:
        logger.debug("Original subprocess functions already stored.")

    original_popen = sec._original_functions["subprocess.Popen"]

    class SecurePopen(original_popen):
        """Secure wrapper for subprocess.Popen that can be subclassed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            """Initialize SecurePopen with security validation.

            Args:
                *args: Positional arguments passed to subprocess.Popen.
                **kwargs: Keyword arguments passed to subprocess.Popen.

            Raises:
                SecurityError: If shell=True is used when disabled by policy.

            """
            inner_sec = _get_security()
            if inner_sec._bypass_security:
                super().__init__(*args, **kwargs)
                return

            shell = kwargs.get("shell", False)
            if shell and not inner_sec.security_config.get("subprocess", {}).get("allow_shell_true", False):
                error_msg = "subprocess.Popen with shell=True is disabled by security policy"
                logger.error(error_msg)
                logger.warning("Blocked subprocess.Popen with shell=True: %s", args)
                raise SecurityError(error_msg)

            logger.debug("subprocess.Popen: %s", args)

            if shell:
                whitelist: list[str] = inner_sec.security_config.get("subprocess", {}).get("shell_whitelist", [])
                cmd = args[0] if args else kwargs.get("args", "")
                cmd_str = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd) if hasattr(cmd, "__iter__") else str(cmd)

                if whitelist and all(allowed not in cmd_str for allowed in whitelist):
                    error_msg_whitelist = "Command not in shell whitelist: %s"
                    logger.error(error_msg_whitelist, cmd_str)
                    logger.warning(error_msg_whitelist, cmd_str)
                    raise SecurityError(f"Command not in shell whitelist: {cmd_str}")

            super().__init__(*args, **kwargs)

    subprocess.run = _secure_subprocess_run
    subprocess.Popen = SecurePopen
    subprocess.call = _secure_subprocess_call
    subprocess.check_call = _secure_subprocess_check_call
    subprocess.check_output = _secure_subprocess_check_output

    logger.info("Subprocess security patches applied")
    logger.debug("Subprocess functions monkey-patched.")


def _monkey_patch_pickle() -> None:
    """Apply pickle security patches.

    Replaces pickle module functions with secure wrappers that attempt JSON
    serialization first when pickle restrictions are enabled, providing safer
    deserialization alternatives.

    """
    sec = _get_security()
    logger.debug("Applying pickle security patches.")
    if "pickle.dump" not in sec._original_functions:
        logger.debug("Storing original pickle functions.")
        sec._original_functions["pickle.dump"] = pickle.dump
        sec._original_functions["pickle.dumps"] = pickle.dumps
        sec._original_functions["pickle.load"] = pickle.load  # noqa: S301
        sec._original_functions["pickle.loads"] = pickle.loads  # noqa: S301
    else:
        logger.debug("Original pickle functions already stored.")

    pickle.dump = _secure_pickle_dump
    pickle.dumps = _secure_pickle_dumps
    pickle.load = _secure_pickle_load
    pickle.loads = _secure_pickle_loads

    logger.info("Pickle security patches applied")
    logger.debug("Pickle functions monkey-patched.")


def _monkey_patch_hashlib() -> None:
    """Apply hashlib security patches.

    Replaces hashlib module functions with secure wrappers that enforce
    hash algorithm policies, blocking MD5 unless explicitly allowed by
    security configuration.

    """
    sec = _get_security()
    logger.debug("Applying hashlib security patches.")
    if "hashlib.new" not in sec._original_functions:
        logger.debug("Storing original hashlib functions.")
        sec._original_functions["hashlib.new"] = hashlib.new
        sec._original_functions["hashlib.md5"] = hashlib.md5
    else:
        logger.debug("Original hashlib functions already stored.")

    hashlib.new = _secure_hashlib_new
    hashlib.md5 = _secure_hashlib_md5

    logger.info("Hashlib security patches applied")
    logger.debug("Hashlib functions monkey-patched.")


def initialize_security() -> None:
    """Initialize all security patches.

    Initializes the global security enforcement module by creating the
    SecurityEnforcement instance and applying monkey patches to subprocess,
    pickle, and hashlib modules. Configures environment variables based on
    security settings.

    """
    global _security
    logger.debug("Starting security enforcement initialization.")
    if _security is None:
        _security = SecurityEnforcement()
        logger.debug("SecurityEnforcement instance created.")

    logger.info("Initializing Intellicrack security enforcement")

    try:
        _monkey_patch_subprocess()
        _monkey_patch_pickle()
        _monkey_patch_hashlib()

        logger.info("Security config loaded: %s", _security.security_config)
        logger.debug("Security configuration details: %s", json.dumps(_security.security_config, indent=2, cls=DateTimeEncoder))

        if _security.security_config.get("sandbox_analysis", True):
            os.environ["INTELLICRACK_SANDBOX"] = "1"
            logger.debug("INTELLICRACK_SANDBOX environment variable set to 1.")

        if not _security.security_config.get("allow_network_access", False):
            os.environ["INTELLICRACK_NO_NETWORK"] = "1"
            logger.debug("INTELLICRACK_NO_NETWORK environment variable set to 1.")

        logger.info("Security enforcement initialization complete")
        logger.debug("Security enforcement initialization successful.")

    except Exception as e:
        logger.exception("Failed to initialize security: %s", e)
        logger.warning("Running without security enforcement")
        logger.debug("Security enforcement initialization failed with exception: %s", e)


def get_security_status() -> dict[str, Any]:
    """Get current security enforcement status.

    Returns:
        Dictionary containing security status with keys: 'initialized',
        'bypass_enabled', 'config', and 'patches_applied'.

    """
    logger.debug("Retrieving current security enforcement status.")
    if _security is None:
        logger.debug("Security enforcement not yet initialized.")
        return {"initialized": False, "bypass_enabled": False, "config": {}, "patches_applied": {}}
    status: dict[str, Any] = {
        "initialized": bool(_security._original_functions),
        "bypass_enabled": _security._bypass_security,
        "config": _security.security_config,
        "patches_applied": {
            "subprocess": "subprocess.run" in _security._original_functions,
            "pickle": "pickle.dump" in _security._original_functions,
            "hashlib": "hashlib.new" in _security._original_functions,
        },
    }
    logger.debug("Current security status: %s", json.dumps(status, indent=2, cls=DateTimeEncoder))
    return status


class SecurityError(Exception):
    """Raised when a security policy is violated."""


__all__ = [
    "SecurityEnforcement",
    "SecurityError",
    "_security",
    "get_security_status",
    "initialize_security",
    "secure_open",
    "validate_file_input",
]
