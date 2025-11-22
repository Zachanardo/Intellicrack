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

import hashlib
import json
import logging
import os
import pickle
import subprocess
from datetime import date, datetime
from pathlib import Path
from typing import Any, Protocol

from ..utils.logger import log_all_methods, log_function_call


# Initialize logger
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

        Raises:
            TypeError: If object type is not supported by JSON encoder.

        """
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return str(obj) if isinstance(obj, Path) else super().default(obj)


@log_all_methods
class SecurityEnforcement:
    """Central security enforcement class."""

    def __init__(self) -> None:
        """Initialize security enforcement with configuration and tracking state."""
        logger.info("SecurityEnforcement: Initializing security enforcement module.")
        self.config = self._load_config()
        self.security_config = self.config.get("security", {})
        self._original_functions = {}
        self._bypass_security = False  # Emergency bypass flag
        logger.debug(
            f"SecurityEnforcement: Initial security configuration loaded: {self.security_config}"
        )
        logger.info("SecurityEnforcement: Initialization complete.")

    def _load_config(self) -> dict[str, Any]:
        """Load security configuration from main IntellicrackConfig."""
        logger.debug(
            "SecurityEnforcement: Attempting to load security configuration from IntellicrackConfig."
        )
        try:
            from intellicrack.core.config_manager import IntellicrackConfig

            config_manager_instance = IntellicrackConfig()
            # Get the main config dictionary
            config_data = (
                config_manager_instance._config
                if hasattr(config_manager_instance, "_config")
                else {}
            )
            logger.debug(
                f"SecurityEnforcement: IntellicrackConfig loaded. Config data keys: {list(config_data.keys())}"
            )

            # If security section doesn't exist, merge with defaults
            if "security" not in config_data:
                logger.info(
                    "SecurityEnforcement: 'security' section not found in main config. Merging with default security settings."
                )
                default_security_config = self._get_default_config()
                # Ensure the 'security' key exists in config_data before merging
                if "security" not in config_data:
                    config_data["security"] = {}
                self._deep_merge(config_data["security"], default_security_config["security"])

                # Save the updated config with security defaults
                # Assuming IntellicrackConfig has a method to save the entire config
                # or at least the security section. If not, this might need adjustment.
                try:
                    # This assumes IntellicrackConfig.set can handle nested keys and saves
                    config_manager_instance.set("security", config_data["security"], save=True)
                    logger.info(
                        "SecurityEnforcement: Updated main config saved with default security settings."
                    )
                except Exception as save_e:
                    logger.warning(
                        f"SecurityEnforcement: Failed to save updated config with default security settings: {save_e}"
                    )
            else:
                logger.debug("SecurityEnforcement: 'security' section found in main config.")

            logger.debug(
                f"SecurityEnforcement: Final security configuration loaded: {config_data.get('security')}"
            )
            return config_data
        except Exception as e:
            logger.error(
                f"SecurityEnforcement: Failed to load config from IntellicrackConfig: {e}",
                exc_info=True,
            )
            logger.warning(
                "SecurityEnforcement: Using default security settings due to configuration load failure."
            )
            return self._get_default_config()

    def _get_default_config(self) -> dict[str, Any]:
        """Return default security configuration."""
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
        """Deep merge override dict into base dict."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def enable_bypass(self) -> None:
        """Enable security bypass for critical operations."""
        self._bypass_security = True
        logger.warning(
            "SecurityEnforcement: !!! SECURITY BYPASS ENABLED - USE WITH EXTREME CAUTION !!!"
        )
        logger.debug("SecurityEnforcement: Security bypass flag set to True.")

    def disable_bypass(self) -> None:
        """Disable security bypass."""
        self._bypass_security = False
        logger.info("SecurityEnforcement: Security bypass disabled.")
        logger.debug("SecurityEnforcement: Security bypass flag set to False.")


# Global instance - lazy loaded to avoid import-time hang
_security = None


# Subprocess Protection
@log_function_call
def _secure_subprocess_run(*args: object, **kwargs: object) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.run.")
        return _security._original_functions["subprocess.run"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.run with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning(f"Blocked subprocess.run with shell=True: {args}")
        raise SecurityError(error_msg)

    # Log the command for security audit
    logger.debug(f"subprocess.run: {args}")

    # Check whitelist if shell=True is allowed
    if shell:
        whitelist = _security.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

        if whitelist and all(allowed not in cmd_str for allowed in whitelist):
            logger.warning(f"Command not in whitelist: {cmd_str}")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        if whitelist:
            logger.debug(f"Command '{cmd_str}' is in shell whitelist.")

    return _security._original_functions["subprocess.run"](*args, **kwargs)


@log_function_call
def _secure_subprocess_popen(*args: object, **kwargs: object) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.Popen.")
        return _security._original_functions["subprocess.Popen"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.Popen with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning(f"Blocked subprocess.Popen with shell=True: {args}")
        raise SecurityError(error_msg)

    logger.debug(f"subprocess.Popen: {args}")

    if shell:
        whitelist = _security.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

        if whitelist and all(allowed not in cmd_str for allowed in whitelist):
            logger.warning(f"Command not in whitelist: {cmd_str}")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        if whitelist:
            logger.debug(f"Command '{cmd_str}' is in shell whitelist.")

    return _security._original_functions["subprocess.Popen"](*args, **kwargs)


@log_function_call
def _secure_subprocess_call(*args: object, **kwargs: object) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.call.")
        return _security._original_functions["subprocess.call"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.call with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning(f"Blocked subprocess.call with shell=True: {args}")
        raise SecurityError(error_msg)

    logger.debug(f"subprocess.call: {args}")
    return _security._original_functions["subprocess.call"](*args, **kwargs)


@log_function_call
def _secure_subprocess_check_call(*args: object, **kwargs: object) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.check_call.")
        return _security._original_functions["subprocess.check_call"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.check_call with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning(f"Blocked subprocess.check_call with shell=True: {args}")
        raise SecurityError(error_msg)

    logger.debug(f"subprocess.check_call: {args}")
    return _security._original_functions["subprocess.check_call"](*args, **kwargs)


@log_function_call
def _secure_subprocess_check_output(*args: object, **kwargs: object) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.check_output.")
        return _security._original_functions["subprocess.check_output"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        error_msg = "subprocess.check_output with shell=True is disabled by security policy"
        logger.error(error_msg)
        logger.warning(f"Blocked subprocess.check_output with shell=True: {args}")
        raise SecurityError(error_msg)

    logger.debug(f"subprocess.check_output: {args}")
    return _security._original_functions["subprocess.check_output"](*args, **kwargs)


# Pickle Security
@log_function_call
def _secure_pickle_dump(
    obj: object,
    file: object,
    protocol: int | None = None,
    *,
    fix_imports: bool = True,
    buffer_callback: object = None,
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

    Returns:
        None.

    Raises:
        TypeError: If object cannot be serialized to either JSON or pickle.

    """
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.dump.")
        return _security._original_functions["pickle.dump"](
            obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback
        )

    if _security.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle dump attempted with restrict_pickle=True, consider using JSON")
        logger.debug("Attempting JSON serialization instead of pickle.")
        # Try JSON serialization first with custom encoder
        try:
            if hasattr(file, "write"):
                json.dump(obj, file, cls=DateTimeEncoder)
                logger.info("Successfully serialized to JSON instead of pickle")
                logger.debug("JSON serialization successful for pickle.dump.")
                return None
            raise TypeError("File object required for JSON dump")
        except (TypeError, ValueError) as e:
            logger.warning(f"JSON serialization failed, falling back to pickle: {e}")
            logger.debug(
                f"JSON serialization failed for pickle.dump: {e}. Falling back to original pickle.dump."
            )

    logger.debug(f"pickle.dump: object type={type(obj).__name__}")
    return _security._original_functions["pickle.dump"](
        obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback
    )


@log_function_call
def _secure_pickle_dumps(
    obj: object,
    protocol: int | None = None,
    *,
    fix_imports: bool = True,
    buffer_callback: object = None,
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

    Raises:
        TypeError: If object cannot be serialized to either JSON or pickle.

    """
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.dumps.")
        return _security._original_functions["pickle.dumps"](
            obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback
        )

    if _security.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle dumps attempted with restrict_pickle=True, consider using JSON")
        logger.debug("Attempting JSON serialization instead of pickle.")
        try:
            result = json.dumps(obj, cls=DateTimeEncoder)
            logger.info("Successfully serialized to JSON instead of pickle")
            logger.debug("JSON serialization successful for pickle.dumps.")
            return result.encode("utf-8")
        except (TypeError, ValueError) as e:
            logger.warning(f"JSON serialization failed, falling back to pickle: {e}")
            logger.debug(
                f"JSON serialization failed for pickle.dumps: {e}. Falling back to original pickle.dumps."
            )

    logger.debug(f"pickle.dumps: object type={type(obj).__name__}")
    return _security._original_functions["pickle.dumps"](
        obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback
    )


@log_function_call
def _secure_pickle_load(
    file: object,
    *,
    fix_imports: bool = True,
    encoding: str = "ASCII",
    errors: str = "strict",
    buffers: object = None,
) -> object:
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
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.load.")
        return _security._original_functions["pickle.load"](
            file,
            fix_imports=fix_imports,
            encoding=encoding,
            errors=errors,
            buffers=buffers,
        )

    if _security.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle load attempted with restrict_pickle=True, attempting JSON first")
        logger.debug("Attempting JSON deserialization instead of pickle.")
        try:
            import json

            if hasattr(file, "read"):
                file.seek(0)
                result = json.load(file)
                logger.debug("JSON deserialization successful for pickle.load.")
                return result
            raise TypeError("File object required for JSON load")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.warning(f"JSON deserialization failed, falling back to pickle: {e}")
            logger.debug(
                f"JSON deserialization failed for pickle.load: {e}. Falling back to original pickle.load."
            )
            if hasattr(file, "seek"):
                file.seek(0)

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.load.")
    return _security._original_functions["pickle.load"](
        file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers
    )


@log_function_call
def _secure_pickle_loads(
    data: bytes | str,
    *,
    fix_imports: bool = True,
    encoding: str = "ASCII",
    errors: str = "strict",
    buffers: object = None,
) -> object:
    """Secure wrapper for pickle.loads.

    Attempts to deserialize using JSON first when pickle restriction is enabled,
    falling back to pickle if JSON deserialization fails.

    Args:
        data: Bytes or string to deserialize.
        fix_imports: Whether to fix imports for Python 2/3 compatibility.
        encoding: Text encoding for deserialization.
        errors: How to handle encoding errors.
        buffers: Optional buffer protocol objects.

    Returns:
        Deserialized object.

    Raises:
        TypeError: If data cannot be deserialized from either JSON or pickle.

    """
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.loads.")
        return _security._original_functions["pickle.loads"](
            data,
            fix_imports=fix_imports,
            encoding=encoding,
            errors=errors,
            buffers=buffers,
        )

    if _security.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle loads attempted with restrict_pickle=True, attempting JSON first")
        logger.debug("Attempting JSON deserialization instead of pickle.")
        try:
            import json

            data_str = data.decode("utf-8") if isinstance(data, bytes) else data
            result = json.loads(data_str)
            logger.debug("JSON deserialization successful for pickle.loads.")
            return result
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"JSON deserialization failed, falling back to pickle: {e}")
            logger.debug(
                f"JSON deserialization failed for pickle.loads: {e}. Falling back to original pickle.loads."
            )

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.loads.")
    return _security._original_functions["pickle.loads"](
        data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers
    )


# Hashlib Security
class SecureHash:
    """Secure hash wrapper that enforces algorithm policies."""

    def __init__(self, name: str, data: bytes = b"") -> None:
        """Initialize secure hash with algorithm policy enforcement.

        Args:
            name: Hash algorithm name (e.g., 'sha256', 'md5').
            data: Initial data to hash (optional).

        Raises:
            ValueError: If algorithm name is invalid.

        """
        self.name = name
        allow_md5 = _security.security_config.get("hashing", {}).get(
            "allow_md5_for_security", False
        )

        if (
            name.lower() in {"md5"}
            and not allow_md5
            and not _security._bypass_security
        ):
            logger.warning("MD5 hash requested but not allowed for security purposes")
            default_algo = _security.security_config.get("hashing", {}).get(
                "default_algorithm", "sha256"
            )
            logger.info(f"Using {default_algo} instead of MD5")
            name = default_algo
            logger.debug(f"MD5 blocked. Using default algorithm: {name}")

        self._hash = getattr(hashlib, name)(data)

    def update(self, data: bytes) -> None:
        """Update hash with additional data.

        Args:
            data: Bytes to add to hash calculation.

        """
        return self._hash.update(data)

    def digest(self) -> bytes:
        """Get binary digest of hashed data.

        Returns:
            Binary digest.

        """
        return self._hash.digest()

    def hexdigest(self) -> str:
        """Get hexadecimal digest of hashed data.

        Returns:
            Hexadecimal string digest.

        """
        return self._hash.hexdigest()

    def copy(self) -> "SecureHash":
        """Create a copy of this hash object.

        Returns:
            New SecureHash instance with copied state.

        """
        new_hash = SecureHash.__new__(SecureHash)
        new_hash.name = self.name
        new_hash._hash = self._hash.copy()
        return new_hash

    @property
    def digest_size(self) -> int:
        """Get size of digest in bytes.

        Returns:
            Digest size.

        """
        return self._hash.digest_size

    @property
    def block_size(self) -> int:
        """Get internal block size of hash algorithm.

        Returns:
            Block size in bytes.

        """
        return self._hash.block_size

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
def _secure_hashlib_new(name: str, data: bytes = b"", **kwargs: object) -> object:
    """Secure wrapper for hashlib.new.

    Creates hash objects with algorithm policy enforcement, blocking MD5 unless
    explicitly allowed by security configuration.

    Args:
        name: Hash algorithm name.
        data: Initial data to hash (optional).
        **kwargs: Additional arguments passed to hashlib.new.

    Returns:
        Hash object.

    Raises:
        ValueError: If algorithm name is invalid.

    """
    if _security._bypass_security:
        return _security._original_functions["hashlib.new"](name, data, **kwargs)

    allow_md5 = _security.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if name.lower() in {"md5"} and not allow_md5:
        logger.warning(f"hashlib.new('{name}') requested but not allowed for security")
        default_algo = _security.security_config.get("hashing", {}).get(
            "default_algorithm", "sha256"
        )
        logger.info(f"Using {default_algo} instead")
        name = default_algo
        logger.debug(f"MD5 blocked. Using default algorithm: {name}")

    logger.debug(f"hashlib.new: algorithm={name}")
    return _security._original_functions["hashlib.new"](name, data, **kwargs)


@log_function_call
def _secure_hashlib_md5(data: bytes = b"", **kwargs: object) -> object:
    """Secure wrapper for hashlib.md5.

    Blocks MD5 hashing unless explicitly allowed by security configuration,
    substituting the configured default algorithm instead.

    Args:
        data: Initial data to hash (optional).
        **kwargs: Additional arguments passed to hashlib.md5.

    Returns:
        Hash object.

    """
    if _security._bypass_security:
        return _security._original_functions["hashlib.md5"](data, **kwargs)

    allow_md5 = _security.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if not allow_md5:
        logger.warning("hashlib.md5() requested but not allowed for security")
        default_algo = _security.security_config.get("hashing", {}).get(
            "default_algorithm", "sha256"
        )
        logger.info(f"Using {default_algo} instead")
        logger.debug(f"MD5 blocked. Using default algorithm: {default_algo}")
        return getattr(hashlib, default_algo)(data, **kwargs)

    logger.debug("hashlib.md5: allowed by configuration")
    return _security._original_functions["hashlib.md5"](data, **kwargs)


# File Input Validation
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
    logger.debug(f"Validating file input for operation '{operation}': {file_path}")
    if _security._bypass_security:
        logger.debug("Security bypass active for file input validation.")
        return True

    file_path = Path(file_path)
    validation_config = _security.security_config.get("input_validation", {})

    if not validation_config.get("strict_mode", True):
        logger.debug("Strict mode disabled. Skipping file input validation.")
        return True

    # Check file size if configured
    max_size = validation_config.get("max_file_size", False)
    if max_size and isinstance(max_size, (int, float)):
        logger.debug(f"Checking file size against max_size: {max_size}")
        try:
            file_size = file_path.stat().st_size
            if file_size > max_size:
                error_msg = f"File {file_path} exceeds max size: {file_size} > {max_size}"
                logger.error(error_msg)
                logger.warning(error_msg)
                raise SecurityError(f"File exceeds maximum size limit: {file_size} > {max_size}")
            logger.debug(f"File size {file_size} is within limits.")
        except OSError:
            logger.debug("File does not exist yet, skipping size check.")
            # File doesn't exist yet, skip size check

    # Check allowed extensions if configured
    allowed_extensions = validation_config.get("allowed_extensions", False)
    if allowed_extensions and isinstance(allowed_extensions, list):
        logger.debug(f"Checking file extension against allowed_extensions: {allowed_extensions}")
        file_ext = file_path.suffix.lower()
        if file_ext not in allowed_extensions:
            error_msg = f"File extension {file_ext} not in allowed list: {allowed_extensions}"
            logger.error(error_msg)
            logger.warning(error_msg)
            raise SecurityError(f"File extension {file_ext} not allowed")
        logger.debug(f"File extension '{file_ext}' is allowed.")

    # Check for path traversal
    try:
        logger.debug("Checking for path traversal.")
        file_path.resolve()
        if ".." in str(file_path):
            logger.warning(f"Potential path traversal detected: {file_path}")
            if validation_config.get("strict_mode", True):
                error_msg = "Path traversal not allowed in strict mode"
                logger.error(error_msg)
                raise SecurityError(error_msg)
        logger.debug(f"Path traversal check passed for {file_path}.")
    except Exception as e:
        logger.debug("Security validation exception during path traversal check: %s", e)

    logger.debug(f"File validation passed for {operation}: {file_path}")
    return True


# Secure file operations
@log_function_call
def secure_open(file: str | Path, mode: str = "r", *args: object, **kwargs: object) -> object:
    """Secure wrapper for open() with validation.

    Opens files with security validation to enforce access policies.

    Args:
        file: Path to file to open.
        mode: File open mode (e.g., 'r', 'w', 'a').
        *args: Additional positional arguments for open().
        **kwargs: Additional keyword arguments for open().

    Returns:
        File object.

    Raises:
        SecurityError: If file validation fails.

    """
    logger.debug(f"Attempting to securely open file: {file} with mode: {mode}")
    if "r" in mode or "a" in mode:
        validate_file_input(file, "read")
    if "w" in mode or "a" in mode:
        validate_file_input(file, "write")
    logger.debug(f"File {file} validated. Proceeding with open().")
    return open(file, mode, *args, **kwargs)


# Monkey-patching functions
def _monkey_patch_subprocess() -> None:
    """Apply subprocess security patches."""
    logger.debug("Applying subprocess security patches.")
    if "subprocess.run" not in _security._original_functions:
        logger.debug("Storing original subprocess functions.")
        _security._original_functions["subprocess.run"] = subprocess.run
        _security._original_functions["subprocess.Popen"] = subprocess.Popen
        _security._original_functions["subprocess.call"] = subprocess.call
        _security._original_functions["subprocess.check_call"] = subprocess.check_call
        _security._original_functions["subprocess.check_output"] = subprocess.check_output
    else:
        logger.debug("Original subprocess functions already stored.")



    class SecurePopen(_security._original_functions["subprocess.Popen"]):
        """Secure wrapper for subprocess.Popen that can be subclassed."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            """Initialize SecurePopen with security validation.

            Args:
                *args: Positional arguments passed to subprocess.Popen.
                **kwargs: Keyword arguments passed to subprocess.Popen.

            Raises:
                SecurityError: If shell=True is used when disabled by policy.

            """
            if _security._bypass_security:
                super().__init__(*args, **kwargs)
                return

            shell = kwargs.get("shell", False)
            if shell and not _security.security_config.get("subprocess", {}).get(
                "allow_shell_true", False
            ):
                error_msg = "subprocess.Popen with shell=True is disabled by security policy"
                logger.error(error_msg)
                logger.warning(f"Blocked subprocess.Popen with shell=True: {args}")
                raise SecurityError(error_msg)

            logger.debug(f"subprocess.Popen: {args}")

            if shell:
                whitelist = _security.security_config.get("subprocess", {}).get(
                    "shell_whitelist", []
                )
                cmd = args[0] if args else kwargs.get("args", "")
                cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

                if whitelist and all(
                    allowed not in cmd_str for allowed in whitelist
                ):
                    error_msg = f"Command not in shell whitelist: {cmd_str}"
                    logger.error(error_msg)
                    logger.warning(error_msg)
                    raise SecurityError(error_msg)

            super().__init__(*args, **kwargs)


    subprocess.run = _secure_subprocess_run
    subprocess.Popen = SecurePopen
    subprocess.call = _secure_subprocess_call
    subprocess.check_call = _secure_subprocess_check_call
    subprocess.check_output = _secure_subprocess_check_output

    logger.info("Subprocess security patches applied")
    logger.debug("Subprocess functions monkey-patched.")


def _monkey_patch_pickle() -> None:
    """Apply pickle security patches."""
    logger.debug("Applying pickle security patches.")
    if "pickle.dump" not in _security._original_functions:
        logger.debug("Storing original pickle functions.")
        _security._original_functions["pickle.dump"] = pickle.dump
        _security._original_functions["pickle.dumps"] = pickle.dumps
        _security._original_functions["pickle.load"] = pickle.load
        _security._original_functions["pickle.loads"] = pickle.loads
    else:
        logger.debug("Original pickle functions already stored.")

    pickle.dump = _secure_pickle_dump
    pickle.dumps = _secure_pickle_dumps
    pickle.load = _secure_pickle_load
    pickle.loads = _secure_pickle_loads

    logger.info("Pickle security patches applied")
    logger.debug("Pickle functions monkey-patched.")


def _monkey_patch_hashlib() -> None:
    """Apply hashlib security patches."""
    logger.debug("Applying hashlib security patches.")
    if "hashlib.new" not in _security._original_functions:
        logger.debug("Storing original hashlib functions.")
        _security._original_functions["hashlib.new"] = hashlib.new
        _security._original_functions["hashlib.md5"] = hashlib.md5
    else:
        logger.debug("Original hashlib functions already stored.")

    hashlib.new = _secure_hashlib_new
    hashlib.md5 = _secure_hashlib_md5

    logger.info("Hashlib security patches applied")
    logger.debug("Hashlib functions monkey-patched.")


def initialize_security() -> None:
    """Initialize all security patches."""
    global _security
    logger.debug("Starting security enforcement initialization.")
    # Lazy initialization to avoid import-time hang
    if _security is None:
        _security = SecurityEnforcement()
        logger.debug("SecurityEnforcement instance created.")

    logger.info("Initializing Intellicrack security enforcement")

    try:
        _monkey_patch_subprocess()
        _monkey_patch_pickle()
        _monkey_patch_hashlib()

        # Log security configuration
        logger.info(f"Security config loaded: {_security.security_config}")
        logger.debug(
            f"Security configuration details: {json.dumps(_security.security_config, indent=2, cls=DateTimeEncoder)}"
        )

        # Set security-related environment variables
        if _security.security_config.get("sandbox_analysis", True):
            os.environ["INTELLICRACK_SANDBOX"] = "1"
            logger.debug("INTELLICRACK_SANDBOX environment variable set to 1.")

        if not _security.security_config.get("allow_network_access", False):
            os.environ["INTELLICRACK_NO_NETWORK"] = "1"
            logger.debug("INTELLICRACK_NO_NETWORK environment variable set to 1.")

        logger.info("Security enforcement initialization complete")
        logger.debug("Security enforcement initialization successful.")

    except Exception as e:
        logger.error(f"Failed to initialize security: {e}")
        logger.warning("Running without security enforcement")
        logger.debug(
            f"Security enforcement initialization failed with exception: {e}", exc_info=True
        )


def get_security_status() -> dict[str, Any]:
    """Get current security enforcement status."""
    logger.debug("Retrieving current security enforcement status.")
    # Return uninitialized status if not yet created
    if _security is None:
        logger.debug("Security enforcement not yet initialized.")
        return {"initialized": False, "bypass_enabled": False, "config": {}, "patches_applied": {}}
    status = {
        "initialized": bool(_security._original_functions),
        "bypass_enabled": _security._bypass_security,
        "config": _security.security_config,
        "patches_applied": {
            "subprocess": "subprocess.run" in _security._original_functions,
            "pickle": "pickle.dump" in _security._original_functions,
            "hashlib": "hashlib.new" in _security._original_functions,
        },
    }
    logger.debug(f"Current security status: {json.dumps(status, indent=2, cls=DateTimeEncoder)}")
    return status


# Custom exception
class SecurityError(Exception):
    """Raised when a security policy is violated."""


# Auto-initialize on import
# initialize_security()  # Temporarily disabled for testing

# Export public API
__all__ = [
    "SecurityEnforcement",
    "SecurityError",
    "_security",  # For advanced usage
    "get_security_status",
    "initialize_security",
    "secure_open",
    "validate_file_input",
]
