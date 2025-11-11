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
from typing import TYPE_CHECKING, Any

from ..utils.logger import log_all_methods

if TYPE_CHECKING:
    from intellicrack.core.config_manager import IntellicrackConfig

# Initialize logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class DateTimeEncoder(json.JSONEncoder):
    """Customize JSON encoder for datetime and date objects."""

    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


@log_all_methods
class SecurityEnforcement:
    """Central security enforcement class."""

    def __init__(self) -> None:
        """Initialize security enforcement with configuration and tracking state."""
        self.config = self._load_config()
        self.security_config = self.config.get("security", {})
        self._original_functions = {}
        self._bypass_security = False  # Emergency bypass flag

    def _load_config(self) -> dict[str, Any]:
        """Load security configuration from main IntellicrackConfig."""
        logger.debug("Loading security configuration.")
        try:
            from intellicrack.core.config_manager import IntellicrackConfig
            config = IntellicrackConfig()
            # Get the main config dictionary
            config_data = config._config if hasattr(config, "_config") else {}

            # If security section doesn't exist, merge with defaults
            if "security" not in config_data:
                logger.info("Security section not found in config, using defaults")
                logger.debug("Security section not found in config. Merging with default settings.")
                default_config = self._get_default_config()
                config_data.update(default_config)
                # Save the updated config with security defaults
                if hasattr(config, "save"):
                    config.save()
                    logger.debug("Updated config saved with default security settings.")
            else:
                logger.debug("Security section found in config.")

            logger.debug(f"Security configuration loaded: {config_data.get('security')}")
            return config_data
        except Exception as e:
            logger.error(f"Failed to load config from IntellicrackConfig: {e}")
            logger.warning("Using default security settings")
            logger.debug("Failed to load config. Using default security settings.")
            return self._get_default_config()

    def _get_default_config(self) -> dict[str, Any]:
        """Return default security configuration."""
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

    def enable_bypass(self) -> None:
        """Enable security bypass for critical operations."""
        self._bypass_security = True
        logger.warning("Security bypass enabled - use with caution!")
        logger.debug("Security bypass flag set to True.")

    def disable_bypass(self) -> None:
        """Disable security bypass."""
        self._bypass_security = False
        logger.info("Security bypass disabled")
        logger.debug("Security bypass flag set to False.")


# Global instance - lazy loaded to avoid import-time hang
_security = None


from ..utils.logger import log_all_methods, log_function_call


# Subprocess Protection
@log_function_call
def _secure_subprocess_run(*args, **kwargs):
    """Secure wrapper for subprocess.run."""
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.run.")
        return _security._original_functions["subprocess.run"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        logger.warning(f"Blocked subprocess.run with shell=True: {args}")
        raise SecurityError("subprocess.run with shell=True is disabled by security policy")

    # Log the command for security audit
    logger.debug(f"subprocess.run: {args}")

    # Check whitelist if shell=True is allowed
    if shell:
        whitelist = _security.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

        if whitelist and not any(allowed in cmd_str for allowed in whitelist):
            logger.warning(f"Command not in whitelist: {cmd_str}")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        elif whitelist:
            logger.debug(f"Command '{cmd_str}' is in shell whitelist.")

    return _security._original_functions["subprocess.run"](*args, **kwargs)


@log_function_call
def _secure_subprocess_popen(*args, **kwargs):
    """Secure wrapper for subprocess.Popen."""
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.Popen.")
        return _security._original_functions["subprocess.Popen"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        logger.warning(f"Blocked subprocess.Popen with shell=True: {args}")
        raise SecurityError("subprocess.Popen with shell=True is disabled by security policy")

    logger.debug(f"subprocess.Popen: {args}")

    if shell:
        whitelist = _security.security_config.get("subprocess", {}).get("shell_whitelist", [])
        cmd = args[0] if args else kwargs.get("args", "")
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

        if whitelist and not any(allowed in cmd_str for allowed in whitelist):
            logger.warning(f"Command not in whitelist: {cmd_str}")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
        elif whitelist:
            logger.debug(f"Command '{cmd_str}' is in shell whitelist.")

    return _security._original_functions["subprocess.Popen"](*args, **kwargs)


@log_function_call
def _secure_subprocess_call(*args, **kwargs):
    """Secure wrapper for subprocess.call."""
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.call.")
        return _security._original_functions["subprocess.call"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        logger.warning(f"Blocked subprocess.call with shell=True: {args}")
        raise SecurityError("subprocess.call with shell=True is disabled by security policy")

    logger.debug(f"subprocess.call: {args}")
    return _security._original_functions["subprocess.call"](*args, **kwargs)


@log_function_call
def _secure_subprocess_check_call(*args, **kwargs):
    """Secure wrapper for ``subprocess.check_call``."""
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.check_call.")
        return _security._original_functions["subprocess.check_call"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        logger.warning(f"Blocked subprocess.check_call with shell=True: {args}")
        raise SecurityError("subprocess.check_call with shell=True is disabled by security policy")

    logger.debug(f"subprocess.check_call: {args}")
    return _security._original_functions["subprocess.check_call"](*args, **kwargs)


@log_function_call
def _secure_subprocess_check_output(*args, **kwargs):
    """Secure wrapper for ``subprocess.check_output``."""
    if _security._bypass_security:
        logger.debug("Security bypass active for subprocess.check_output.")
        return _security._original_functions["subprocess.check_output"](*args, **kwargs)

    shell = kwargs.get("shell", False)
    if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
        logger.warning(f"Blocked subprocess.check_output with shell=True: {args}")
        raise SecurityError("subprocess.check_output with shell=True is disabled by security policy")

    logger.debug(f"subprocess.check_output: {args}")
    return _security._original_functions["subprocess.check_output"](*args, **kwargs)


# Pickle Security
@log_function_call
def _secure_pickle_dump(obj, file, protocol=None, *, fix_imports=True, buffer_callback=None):
    """Secure wrapper for pickle.dump."""
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.dump.")
        return _security._original_functions["pickle.dump"](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

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
            logger.debug(f"JSON serialization failed for pickle.dump: {e}. Falling back to original pickle.dump.")

    logger.debug(f"pickle.dump: object type={type(obj).__name__}")
    return _security._original_functions["pickle.dump"](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)


@log_function_call
def _secure_pickle_dumps(obj, protocol=None, *, fix_imports=True, buffer_callback=None):
    """Secure wrapper for pickle.dumps."""
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.dumps.")
        return _security._original_functions["pickle.dumps"](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

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
            logger.debug(f"JSON serialization failed for pickle.dumps: {e}. Falling back to original pickle.dumps.")

    logger.debug(f"pickle.dumps: object type={type(obj).__name__}")
    return _security._original_functions["pickle.dumps"](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)


@log_function_call
def _secure_pickle_load(file, *, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
    """Secure wrapper for pickle.load."""
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.load.")
        return _security._original_functions["pickle.load"](
            file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers,
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
            logger.debug(f"JSON deserialization failed for pickle.load: {e}. Falling back to original pickle.load.")
            if hasattr(file, "seek"):
                file.seek(0)

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.load.")
    return _security._original_functions["pickle.load"](file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)


@log_function_call
def _secure_pickle_loads(data, *, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
    """Secure wrapper for pickle.loads."""
    if _security._bypass_security:
        logger.debug("Security bypass active for pickle.loads.")
        return _security._original_functions["pickle.loads"](
            data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers,
        )

    if _security.security_config.get("serialization", {}).get("restrict_pickle", True):
        logger.warning("Pickle loads attempted with restrict_pickle=True, attempting JSON first")
        logger.debug("Attempting JSON deserialization instead of pickle.")
        try:
            import json

            if isinstance(data, bytes):
                data_str = data.decode("utf-8")
            else:
                data_str = data
            result = json.loads(data_str)
            logger.debug("JSON deserialization successful for pickle.loads.")
            return result
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
            logger.warning(f"JSON deserialization failed, falling back to pickle: {e}")
            logger.debug(f"JSON deserialization failed for pickle.loads: {e}. Falling back to original pickle.loads.")

    logger.warning("Loading pickle data - ensure source is trusted!")
    logger.debug("Proceeding with original pickle.loads.")
    return _security._original_functions["pickle.loads"](data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)


# Hashlib Security
class SecureHash:
    """Secure hash wrapper that enforces algorithm policies."""

    def __init__(self, name, data=b"") -> None:
        self.name = name
        allow_md5 = _security.security_config.get("hashing", {}).get("allow_md5_for_security", False)

        if name.lower() in ["md5"] and not allow_md5 and not _security._bypass_security:
            logger.warning("MD5 hash requested but not allowed for security purposes")
            default_algo = _security.security_config.get("hashing", {}).get("default_algorithm", "sha256")
            logger.info(f"Using {default_algo} instead of MD5")
            name = default_algo
            logger.debug(f"MD5 blocked. Using default algorithm: {name}")

        self._hash = getattr(hashlib, name)(data)

    def update(self, data):
        return self._hash.update(data)

    def digest(self):
        return self._hash.digest()

    def hexdigest(self):
        return self._hash.hexdigest()

    def copy(self):
        new_hash = SecureHash.__new__(SecureHash)
        new_hash.name = self.name
        new_hash._hash = self._hash.copy()
        return new_hash

    @property
    def digest_size(self):
        return self._hash.digest_size

    @property
    def block_size(self):
        return self._hash.block_size

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value) -> None:
        self._name = value


@log_function_call
def _secure_hashlib_new(name, data=b"", **kwargs):
    """Secure wrapper for hashlib.new."""
    if _security._bypass_security:
        return _security._original_functions["hashlib.new"](name, data, **kwargs)

    allow_md5 = _security.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if name.lower() in ["md5"] and not allow_md5:
        logger.warning(f"hashlib.new('{name}') requested but not allowed for security")
        default_algo = _security.security_config.get("hashing", {}).get("default_algorithm", "sha256")
        logger.info(f"Using {default_algo} instead")
        name = default_algo
        logger.debug(f"MD5 blocked. Using default algorithm: {name}")

    logger.debug(f"hashlib.new: algorithm={name}")
    return _security._original_functions["hashlib.new"](name, data, **kwargs)


@log_function_call
def _secure_hashlib_md5(data=b"", **kwargs):
    """Secure wrapper for hashlib.md5."""
    if _security._bypass_security:
        return _security._original_functions["hashlib.md5"](data, **kwargs)

    allow_md5 = _security.security_config.get("hashing", {}).get("allow_md5_for_security", False)

    if not allow_md5:
        logger.warning("hashlib.md5() requested but not allowed for security")
        default_algo = _security.security_config.get("hashing", {}).get("default_algorithm", "sha256")
        logger.info(f"Using {default_algo} instead")
        logger.debug(f"MD5 blocked. Using default algorithm: {default_algo}")
        return getattr(hashlib, default_algo)(data, **kwargs)

    logger.debug("hashlib.md5: allowed by configuration")
    return _security._original_functions["hashlib.md5"](data, **kwargs)


# File Input Validation
@log_function_call
def validate_file_input(file_path: str | Path, operation: str = "read") -> bool:
    """Validate file input based on security configuration."""
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
                logger.warning(f"File {file_path} exceeds max size: {file_size} > {max_size}")
                raise SecurityError(f"File exceeds maximum size limit: {file_size} > {max_size}")
            logger.debug(f"File size {file_size} is within limits.")
        except OSError:
            logger.debug("File does not exist yet, skipping size check.")
            pass  # File doesn't exist yet, skip size check

    # Check allowed extensions if configured
    allowed_extensions = validation_config.get("allowed_extensions", False)
    if allowed_extensions and isinstance(allowed_extensions, list):
        logger.debug(f"Checking file extension against allowed_extensions: {allowed_extensions}")
        file_ext = file_path.suffix.lower()
        if file_ext not in allowed_extensions:
            logger.warning(f"File extension {file_ext} not in allowed list: {allowed_extensions}")
            raise SecurityError(f"File extension {file_ext} not allowed")
        logger.debug(f"File extension '{file_ext}' is allowed.")

    # Check for path traversal
    try:
        logger.debug("Checking for path traversal.")
        resolved_path = file_path.resolve()
        if ".." in str(file_path):
            logger.warning(f"Potential path traversal detected: {file_path}")
            if validation_config.get("strict_mode", True):
                raise SecurityError("Path traversal not allowed in strict mode")
        logger.debug(f"Path traversal check passed for {file_path}.")
    except Exception as e:
        logger.debug("Security validation exception during path traversal check: %s", e)

    logger.debug(f"File validation passed for {operation}: {file_path}")
    return True


# Secure file operations
@log_function_call
def secure_open(file, mode="r", *args, **kwargs):
    """Secure wrapper for open() with validation."""
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

    # Create a subclassable Popen wrapper
    class SecurePopen(_security._original_functions["subprocess.Popen"]):
        """Secure wrapper for subprocess.Popen that can be subclassed."""

        def __init__(self, *args, **kwargs) -> None:
            if _security._bypass_security:
                super().__init__(*args, **kwargs)
                return

            shell = kwargs.get("shell", False)
            if shell and not _security.security_config.get("subprocess", {}).get("allow_shell_true", False):
                logger.warning(f"Blocked subprocess.Popen with shell=True: {args}")
                raise SecurityError("subprocess.Popen with shell=True is disabled by security policy")

            logger.debug(f"subprocess.Popen: {args}")

            if shell:
                whitelist = _security.security_config.get("subprocess", {}).get("shell_whitelist", [])
                cmd = args[0] if args else kwargs.get("args", "")
                cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)

                if whitelist and not any(allowed in cmd_str for allowed in whitelist):
                    logger.warning(f"Command not in whitelist: {cmd_str}")
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
        logger.debug(f"Security configuration details: {json.dumps(_security.security_config, indent=2, cls=DateTimeEncoder)}")

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
        logger.debug(f"Security enforcement initialization failed with exception: {e}", exc_info=True)


def get_security_status() -> dict[str, Any]:
    """Get current security enforcement status."""
    global _security
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
