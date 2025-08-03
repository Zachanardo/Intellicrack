"""
Security Enforcement Module for Intellicrack
Implements security policies defined in intellicrack_config.json
"""
import hashlib
import json
import logging
import os
import pickle
import subprocess
from pathlib import Path
from typing import Any, Dict, Union

# Initialize structured logger
try:
    from ..utils.logger import get_logger, log_security_alert
    logger = get_logger(__name__)
    STRUCTURED_LOGGING = True
except ImportError:
    # Fallback to traditional logging
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    STRUCTURED_LOGGING = False

def _log_security_event(event_type: str, severity: str = "medium", **details):
    """Log security events with structured or traditional logging."""
    if STRUCTURED_LOGGING:
        log_security_alert(event_type, severity, **details)
    else:
        level_map = {"low": "info", "medium": "warning", "high": "error", "critical": "critical"}
        log_method = getattr(logger, level_map.get(severity, "warning"))
        log_method(f"Security Event [{severity.upper()}]: {event_type} - {details}")

class SecurityEnforcement:
    """Central security enforcement class"""

    def __init__(self):
        """Initialize security enforcement with configuration and tracking state."""
        self.config = self._load_config()
        self.security_config = self.config.get('security', {})
        self._original_functions = {}
        self._bypass_security = False  # Emergency bypass flag

    def _load_config(self) -> Dict[str, Any]:
        """Load security configuration from centralized config system"""
        try:
            from .config_manager import get_config
            config_manager = get_config()
            # Return full config with security section prioritized
            centralized_config = dict(config_manager._config)
            if 'security' in centralized_config:
                return centralized_config
            else:
                # Add default security config to centralized system
                default_config = self._get_default_config()
                config_manager.set('security', default_config['security'])
                return default_config
        except ImportError:
            logger.debug("Centralized config not available, trying local files")
        
        # Fallback to original file-based loading
        config_paths = [
            Path(__file__).parent.parent.parent / 'config' / 'intellicrack_config.json',
            Path.cwd() / 'config' / 'intellicrack_config.json',
            Path.home() / '.intellicrack' / 'intellicrack_config.json'
        ]

        for config_path in config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        if STRUCTURED_LOGGING:
                            logger.info("Security configuration loaded", 
                                      config_path=str(config_path), 
                                      method="fallback",
                                      category="config")
                        else:
                            logger.info(f"Security config loaded from {config_path} (fallback)")
                        return config
                except Exception as e:
                    if STRUCTURED_LOGGING:
                        logger.error("Failed to load security configuration",
                                   config_path=str(config_path),
                                   error=str(e),
                                   category="config")
                    else:
                        logger.error(f"Failed to load config from {config_path}: {e}")

        if STRUCTURED_LOGGING:
            logger.warning("Using default security configuration",
                         reason="no_config_found",
                         category="config")
        else:
            logger.warning("No configuration found, using default security settings")
        return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default security configuration"""
        return {
            "security": {
                "sandbox_analysis": True,
                "allow_network_access": False,
                "log_sensitive_data": False,
                "encrypt_config": False,
                "hashing": {
                    "default_algorithm": "sha256",
                    "allow_md5_for_security": False
                },
                "subprocess": {
                    "allow_shell_true": False,
                    "shell_whitelist": []
                },
                "serialization": {
                    "default_format": "json",
                    "restrict_pickle": True
                },
                "input_validation": {
                    "strict_mode": True,
                    "max_file_size": False,
                    "allowed_extensions": False
                }
            }
        }

    def enable_bypass(self):
        """Enable security bypass for critical operations"""
        self._bypass_security = True
        _log_security_event("security_bypass_enabled", "high",
                          reason="critical_operation_requested",
                          warning="use_with_caution")

    def disable_bypass(self):
        """Disable security bypass"""
        self._bypass_security = False
        _log_security_event("security_bypass_disabled", "medium",
                          status="normal_operations_restored")

# Global instance
_security = SecurityEnforcement()

# Subprocess Protection
def _secure_subprocess_run(*args, **kwargs):
    """Secure wrapper for subprocess.run"""
    if _security._bypass_security:
        return _security._original_functions['subprocess.run'](*args, **kwargs)

    shell = kwargs.get('shell', False)
    if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
        _log_security_event("subprocess_blocked", "high",
                          function="subprocess.run",
                          reason="shell_disabled",
                          command=str(args),
                          policy="security_enforcement")
        raise SecurityError("subprocess.run with shell=True is disabled by security policy")

    # Log the command for security audit
    logger.debug(f"subprocess.run: {args}")

    # Check whitelist if shell=True is allowed
    if shell:
        whitelist = _security.security_config.get('subprocess', {}).get('shell_whitelist', [])
        cmd = args[0] if args else kwargs.get('args', '')
        cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)

        if whitelist and not any(allowed in cmd_str for allowed in whitelist):
            logger.warning(f"Command not in whitelist: {cmd_str}")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")

    return _security._original_functions['subprocess.run'](*args, **kwargs)

def _secure_subprocess_popen(*args, **kwargs):
    """Secure wrapper for subprocess.Popen"""
    if _security._bypass_security:
        return _security._original_functions['subprocess.Popen'](*args, **kwargs)

    shell = kwargs.get('shell', False)
    if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
        _log_security_event("subprocess_blocked", "high",
                          function="subprocess.Popen",
                          reason="shell_disabled",
                          command=str(args),
                          policy="security_enforcement")
        raise SecurityError("subprocess.Popen with shell=True is disabled by security policy")

    if STRUCTURED_LOGGING:
        logger.debug("Subprocess operation", 
                    function="subprocess.Popen",
                    command=str(args),
                    category="subprocess")
    else:
        logger.debug(f"subprocess.Popen: {args}")

    if shell:
        whitelist = _security.security_config.get('subprocess', {}).get('shell_whitelist', [])
        cmd = args[0] if args else kwargs.get('args', '')
        cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)

        if whitelist and not any(allowed in cmd_str for allowed in whitelist):
            _log_security_event("command_not_whitelisted", "medium",
                              function="subprocess.Popen",
                              command=cmd_str,
                              whitelist=whitelist,
                              action="blocked")
            raise SecurityError(f"Command not in shell whitelist: {cmd_str}")

    return _security._original_functions['subprocess.Popen'](*args, **kwargs)

def _secure_subprocess_call(*args, **kwargs):
    """Secure wrapper for subprocess.call"""
    if _security._bypass_security:
        return _security._original_functions['subprocess.call'](*args, **kwargs)

    shell = kwargs.get('shell', False)
    if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
        _log_security_event("subprocess_blocked", "high",
                          function="subprocess.call",
                          reason="shell_disabled",
                          command=str(args),
                          policy="security_enforcement")
        raise SecurityError("subprocess.call with shell=True is disabled by security policy")

    if STRUCTURED_LOGGING:
        logger.debug("Subprocess operation",
                    function="subprocess.call",
                    command=str(args),
                    category="subprocess")
    else:
        logger.debug(f"subprocess.call: {args}")
    return _security._original_functions['subprocess.call'](*args, **kwargs)

def _secure_subprocess_check_call(*args, **kwargs):
    """Secure wrapper for subprocess.check_call"""
    if _security._bypass_security:
        return _security._original_functions['subprocess.check_call'](*args, **kwargs)

    shell = kwargs.get('shell', False)
    if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
        _log_security_event("subprocess_blocked", "high",
                          function="subprocess.check_call",
                          reason="shell_disabled",
                          command=str(args),
                          policy="security_enforcement")
        raise SecurityError("subprocess.check_call with shell=True is disabled by security policy")

    if STRUCTURED_LOGGING:
        logger.debug("Subprocess operation",
                    function="subprocess.check_call",
                    command=str(args),
                    category="subprocess")
    else:
        logger.debug(f"subprocess.check_call: {args}")
    return _security._original_functions['subprocess.check_call'](*args, **kwargs)

def _secure_subprocess_check_output(*args, **kwargs):
    """Secure wrapper for subprocess.check_output"""
    if _security._bypass_security:
        return _security._original_functions['subprocess.check_output'](*args, **kwargs)

    shell = kwargs.get('shell', False)
    if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
        _log_security_event("subprocess_blocked", "high",
                          function="subprocess.check_output",
                          reason="shell_disabled",
                          command=str(args),
                          policy="security_enforcement")
        raise SecurityError("subprocess.check_output with shell=True is disabled by security policy")

    if STRUCTURED_LOGGING:
        logger.debug("Subprocess operation",
                    function="subprocess.check_output",
                    command=str(args),
                    category="subprocess")
    else:
        logger.debug(f"subprocess.check_output: {args}")
    return _security._original_functions['subprocess.check_output'](*args, **kwargs)

# Pickle Security
def _secure_pickle_dump(obj, file, protocol=None, *, fix_imports=True, buffer_callback=None):
    """Secure wrapper for pickle.dump"""
    if _security._bypass_security:
        return _security._original_functions['pickle.dump'](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

    if _security.security_config.get('serialization', {}).get('restrict_pickle', True):
        _log_security_event("pickle_restricted", "medium",
                          function="pickle.dump",
                          object_type=type(obj).__name__,
                          action="attempting_json_fallback",
                          policy="restrict_pickle")
        # Try JSON serialization first
        try:
            import json
            if hasattr(file, 'write'):
                json.dump(obj, file)
                if STRUCTURED_LOGGING:
                    logger.info("JSON serialization successful",
                              function="pickle.dump",
                              object_type=type(obj).__name__,
                              action="json_fallback_success",
                              category="serialization")
                else:
                    logger.info("Successfully serialized to JSON instead of pickle")
                return
            else:
                raise TypeError("File object required for JSON dump")
        except (TypeError, ValueError) as e:
            if STRUCTURED_LOGGING:
                logger.warning("JSON serialization failed, using pickle",
                             function="pickle.dump",
                             object_type=type(obj).__name__,
                             error=str(e),
                             action="pickle_fallback",
                             category="serialization")
            else:
                logger.warning(f"JSON serialization failed, falling back to pickle: {e}")

    if STRUCTURED_LOGGING:
        logger.debug("Pickle serialization",
                    function="pickle.dump",
                    object_type=type(obj).__name__,
                    category="serialization")
    else:
        logger.debug(f"pickle.dump: object type={type(obj).__name__}")
    return _security._original_functions['pickle.dump'](obj, file, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

def _secure_pickle_dumps(obj, protocol=None, *, fix_imports=True, buffer_callback=None):
    """Secure wrapper for pickle.dumps"""
    if _security._bypass_security:
        return _security._original_functions['pickle.dumps'](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

    if _security.security_config.get('serialization', {}).get('restrict_pickle', True):
        _log_security_event("pickle_restricted", "medium",
                          function="pickle.dumps",
                          object_type=type(obj).__name__,
                          action="attempting_json_fallback",
                          policy="restrict_pickle")
        try:
            import json
            result = json.dumps(obj)
            if STRUCTURED_LOGGING:
                logger.info("JSON serialization successful",
                          function="pickle.dumps",
                          object_type=type(obj).__name__,
                          action="json_fallback_success",
                          category="serialization")
            else:
                logger.info("Successfully serialized to JSON instead of pickle")
            return result.encode('utf-8')
        except (TypeError, ValueError) as e:
            if STRUCTURED_LOGGING:
                logger.warning("JSON serialization failed, using pickle",
                             function="pickle.dumps",
                             object_type=type(obj).__name__,
                             error=str(e),
                             action="pickle_fallback",
                             category="serialization")
            else:
                logger.warning(f"JSON serialization failed, falling back to pickle: {e}")

    if STRUCTURED_LOGGING:
        logger.debug("Pickle serialization",
                    function="pickle.dumps",
                    object_type=type(obj).__name__,
                    category="serialization")
    else:
        logger.debug(f"pickle.dumps: object type={type(obj).__name__}")
    return _security._original_functions['pickle.dumps'](obj, protocol, fix_imports=fix_imports, buffer_callback=buffer_callback)

def _secure_pickle_load(file, *, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
    """Secure wrapper for pickle.load"""
    if _security._bypass_security:
        return _security._original_functions['pickle.load'](file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)

    if _security.security_config.get('serialization', {}).get('restrict_pickle', True):
        _log_security_event("pickle_restricted", "medium",
                          function="pickle.load",
                          action="attempting_json_fallback",
                          policy="restrict_pickle")
        try:
            import json
            if hasattr(file, 'read'):
                file.seek(0)
                return json.load(file)
            else:
                raise TypeError("File object required for JSON load")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            if STRUCTURED_LOGGING:
                logger.warning("JSON deserialization failed, using pickle",
                             function="pickle.load",
                             error=str(e),
                             action="pickle_fallback",
                             category="serialization")
            else:
                logger.warning(f"JSON deserialization failed, falling back to pickle: {e}")
            if hasattr(file, 'seek'):
                file.seek(0)

    _log_security_event("pickle_load_warning", "medium",
                      function="pickle.load",
                      warning="ensure_source_trusted",
                      category="serialization")
    return _security._original_functions['pickle.load'](file, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)

def _secure_pickle_loads(data, *, fix_imports=True, encoding="ASCII", errors="strict", buffers=None):
    """Secure wrapper for pickle.loads"""
    if _security._bypass_security:
        return _security._original_functions['pickle.loads'](data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)

    if _security.security_config.get('serialization', {}).get('restrict_pickle', True):
        _log_security_event("pickle_restricted", "medium",
                          function="pickle.loads",
                          action="attempting_json_fallback",
                          policy="restrict_pickle")
        try:
            import json
            if isinstance(data, bytes):
                data_str = data.decode('utf-8')
            else:
                data_str = data
            return json.loads(data_str)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
            if STRUCTURED_LOGGING:
                logger.warning("JSON deserialization failed, using pickle",
                             function="pickle.loads",
                             error=str(e),
                             action="pickle_fallback",
                             category="serialization")
            else:
                logger.warning(f"JSON deserialization failed, falling back to pickle: {e}")

    _log_security_event("pickle_load_warning", "medium",
                      function="pickle.loads",
                      warning="ensure_source_trusted",
                      category="serialization")
    return _security._original_functions['pickle.loads'](data, fix_imports=fix_imports, encoding=encoding, errors=errors, buffers=buffers)

# Hashlib Security
class SecureHash:
    """Secure hash wrapper that enforces algorithm policies"""

    def __init__(self, name, data=b''):
        self.name = name
        allow_md5 = _security.security_config.get('hashing', {}).get('allow_md5_for_security', False)

        if name.lower() in ['md5'] and not allow_md5 and not _security._bypass_security:
            default_algo = _security.security_config.get('hashing', {}).get('default_algorithm', 'sha256')
            _log_security_event("md5_blocked", "medium",
                              requested_algorithm="md5",
                              replaced_with=default_algo,
                              reason="security_policy",
                              category="hashing")
            name = default_algo

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
    def name(self, value):
        self._name = value

def _secure_hashlib_new(name, data=b'', **kwargs):
    """Secure wrapper for hashlib.new"""
    if _security._bypass_security:
        return _security._original_functions['hashlib.new'](name, data, **kwargs)

    allow_md5 = _security.security_config.get('hashing', {}).get('allow_md5_for_security', False)

    if name.lower() in ['md5'] and not allow_md5:
        default_algo = _security.security_config.get('hashing', {}).get('default_algorithm', 'sha256')
        _log_security_event("md5_blocked", "medium",
                          function="hashlib.new",
                          requested_algorithm=name,
                          replaced_with=default_algo,
                          reason="security_policy",
                          category="hashing")
        name = default_algo

    if STRUCTURED_LOGGING:
        logger.debug("Hash algorithm operation",
                    function="hashlib.new",
                    algorithm=name,
                    category="hashing")
    else:
        logger.debug(f"hashlib.new: algorithm={name}")
    return _security._original_functions['hashlib.new'](name, data, **kwargs)

def _secure_hashlib_md5(data=b'', **kwargs):
    """Secure wrapper for hashlib.md5"""
    if _security._bypass_security:
        return _security._original_functions['hashlib.md5'](data, **kwargs)

    allow_md5 = _security.security_config.get('hashing', {}).get('allow_md5_for_security', False)

    if not allow_md5:
        default_algo = _security.security_config.get('hashing', {}).get('default_algorithm', 'sha256')
        _log_security_event("md5_blocked", "medium",
                          function="hashlib.md5",
                          requested_algorithm="md5",
                          replaced_with=default_algo,
                          reason="security_policy",
                          category="hashing")
        return getattr(hashlib, default_algo)(data, **kwargs)

    if STRUCTURED_LOGGING:
        logger.debug("MD5 hash allowed by configuration",
                    function="hashlib.md5",
                    algorithm="md5",
                    allowed=True,
                    category="hashing")
    else:
        logger.debug("hashlib.md5: allowed by configuration")
    return _security._original_functions['hashlib.md5'](data, **kwargs)

# File Input Validation
def validate_file_input(file_path: Union[str, Path], operation: str = "read") -> bool:
    """Validate file input based on security configuration"""
    if _security._bypass_security:
        return True

    file_path = Path(file_path)
    validation_config = _security.security_config.get('input_validation', {})

    if not validation_config.get('strict_mode', True):
        return True

    # Check file size if configured
    max_size = validation_config.get('max_file_size', False)
    if max_size and isinstance(max_size, (int, float)):
        try:
            file_size = file_path.stat().st_size
            if file_size > max_size:
                _log_security_event("file_size_exceeded", "high",
                                  file_path=str(file_path),
                                  file_size=file_size,
                                  max_size=max_size,
                                  operation=operation,
                                  category="file_validation")
                raise SecurityError(f"File exceeds maximum size limit: {file_size} > {max_size}")
        except OSError:
            pass  # File doesn't exist yet, skip size check

    # Check allowed extensions if configured
    allowed_extensions = validation_config.get('allowed_extensions', False)
    if allowed_extensions and isinstance(allowed_extensions, list):
        file_ext = file_path.suffix.lower()
        if file_ext not in allowed_extensions:
            _log_security_event("file_extension_blocked", "medium",
                              file_path=str(file_path),
                              file_extension=file_ext,
                              allowed_extensions=allowed_extensions,
                              operation=operation,
                              category="file_validation")
            raise SecurityError(f"File extension {file_ext} not allowed")

    # Check for path traversal
    try:
        file_path.resolve()
        if '..' in str(file_path):
            _log_security_event("path_traversal_detected", "high",
                              file_path=str(file_path),
                              operation=operation,
                              strict_mode=validation_config.get('strict_mode', True),
                              category="file_validation")
            if validation_config.get('strict_mode', True):
                raise SecurityError("Path traversal not allowed in strict mode")
    except Exception:
        pass

    if STRUCTURED_LOGGING:
        logger.debug("File validation passed",
                    file_path=str(file_path),
                    operation=operation,
                    category="file_validation")
    else:
        logger.debug(f"File validation passed for {operation}: {file_path}")
    return True

# Secure file operations
def secure_open(file, mode='r', *args, **kwargs):
    """Secure wrapper for open() with validation"""
    if 'r' in mode or 'a' in mode:
        validate_file_input(file, "read")
    if 'w' in mode or 'a' in mode:
        validate_file_input(file, "write")

    return open(file, mode, *args, **kwargs)

# Monkey-patching functions
def _monkey_patch_subprocess():
    """Apply subprocess security patches"""
    if 'subprocess.run' not in _security._original_functions:
        _security._original_functions['subprocess.run'] = subprocess.run
        _security._original_functions['subprocess.Popen'] = subprocess.Popen
        _security._original_functions['subprocess.call'] = subprocess.call
        _security._original_functions['subprocess.check_call'] = subprocess.check_call
        _security._original_functions['subprocess.check_output'] = subprocess.check_output

    # Create a subclassable Popen wrapper
    class SecurePopen(_security._original_functions['subprocess.Popen']):
        """Secure wrapper for subprocess.Popen that can be subclassed"""
        def __init__(self, *args, **kwargs):
            if _security._bypass_security:
                super().__init__(*args, **kwargs)
                return
                
            shell = kwargs.get('shell', False)
            if shell and not _security.security_config.get('subprocess', {}).get('allow_shell_true', False):
                _log_security_event("subprocess_blocked", "high",
                                  function="SecurePopen.__init__",
                                  reason="shell_disabled",
                                  command=str(args),
                                  policy="security_enforcement")
                raise SecurityError("subprocess.Popen with shell=True is disabled by security policy")

            if STRUCTURED_LOGGING:
                logger.debug("Subprocess operation",
                            function="SecurePopen.__init__",
                            command=str(args),
                            category="subprocess")
            else:
                logger.debug(f"subprocess.Popen: {args}")

            if shell:
                whitelist = _security.security_config.get('subprocess', {}).get('shell_whitelist', [])
                cmd = args[0] if args else kwargs.get('args', '')
                cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)

                if whitelist and not any(allowed in cmd_str for allowed in whitelist):
                    _log_security_event("command_not_whitelisted", "medium",
                                      function="SecurePopen.__init__",
                                      command=cmd_str,
                                      whitelist=whitelist,
                                      action="blocked")
                    raise SecurityError(f"Command not in shell whitelist: {cmd_str}")
                    
            super().__init__(*args, **kwargs)

    subprocess.run = _secure_subprocess_run
    subprocess.Popen = SecurePopen
    subprocess.call = _secure_subprocess_call
    subprocess.check_call = _secure_subprocess_check_call
    subprocess.check_output = _secure_subprocess_check_output

    if STRUCTURED_LOGGING:
        logger.info("Security patches applied",
                   module="subprocess",
                   patches=["run", "Popen", "call", "check_call", "check_output"],
                   category="security_initialization")
    else:
        logger.info("Subprocess security patches applied")

def _monkey_patch_pickle():
    """Apply pickle security patches"""
    if 'pickle.dump' not in _security._original_functions:
        _security._original_functions['pickle.dump'] = pickle.dump
        _security._original_functions['pickle.dumps'] = pickle.dumps
        _security._original_functions['pickle.load'] = pickle.load
        _security._original_functions['pickle.loads'] = pickle.loads

    pickle.dump = _secure_pickle_dump
    pickle.dumps = _secure_pickle_dumps
    pickle.load = _secure_pickle_load
    pickle.loads = _secure_pickle_loads

    if STRUCTURED_LOGGING:
        logger.info("Security patches applied",
                   module="pickle",
                   patches=["dump", "dumps", "load", "loads"],
                   category="security_initialization")
    else:
        logger.info("Pickle security patches applied")

def _monkey_patch_hashlib():
    """Apply hashlib security patches"""
    if 'hashlib.new' not in _security._original_functions:
        _security._original_functions['hashlib.new'] = hashlib.new
        _security._original_functions['hashlib.md5'] = hashlib.md5

    hashlib.new = _secure_hashlib_new
    hashlib.md5 = _secure_hashlib_md5

    if STRUCTURED_LOGGING:
        logger.info("Security patches applied",
                   module="hashlib",
                   patches=["new", "md5"],
                   category="security_initialization")
    else:
        logger.info("Hashlib security patches applied")

def initialize_security():
    """Initialize all security patches"""
    if STRUCTURED_LOGGING:
        logger.info("Initializing security enforcement",
                   system="intellicrack",
                   category="security_initialization")
    else:
        logger.info("Initializing Intellicrack security enforcement")

    try:
        _monkey_patch_subprocess()
        _monkey_patch_pickle()
        _monkey_patch_hashlib()

        # Log security configuration
        if STRUCTURED_LOGGING:
            logger.info("Security configuration loaded",
                       config=_security.security_config,
                       category="security_initialization")
        else:
            logger.info(f"Security config loaded: {_security.security_config}")

        # Set security-related environment variables
        if _security.security_config.get('sandbox_analysis', True):
            os.environ['INTELLICRACK_SANDBOX'] = '1'

        if not _security.security_config.get('allow_network_access', False):
            os.environ['INTELLICRACK_NO_NETWORK'] = '1'

        if STRUCTURED_LOGGING:
            logger.info("Security enforcement initialization complete",
                       environment_vars={
                           'sandbox': os.environ.get('INTELLICRACK_SANDBOX'),
                           'no_network': os.environ.get('INTELLICRACK_NO_NETWORK')
                       },
                       category="security_initialization")
        else:
            logger.info("Security enforcement initialization complete")

    except Exception as e:
        if STRUCTURED_LOGGING:
            logger.error("Failed to initialize security",
                        error=str(e),
                        category="security_initialization")
            logger.warning("Running without security enforcement",
                          status="degraded_mode",
                          category="security_initialization")
        else:
            logger.error(f"Failed to initialize security: {e}")
            logger.warning("Running without security enforcement")

def get_security_status() -> Dict[str, Any]:
    """Get current security enforcement status"""
    return {
        "initialized": bool(_security._original_functions),
        "bypass_enabled": _security._bypass_security,
        "config": _security.security_config,
        "patches_applied": {
            "subprocess": 'subprocess.run' in _security._original_functions,
            "pickle": 'pickle.dump' in _security._original_functions,
            "hashlib": 'hashlib.new' in _security._original_functions
        }
    }

# Custom exception
class SecurityError(Exception):
    """Raised when a security policy is violated"""
    pass

# Auto-initialize on import
# initialize_security()  # Temporarily disabled for testing

# Export public API
__all__ = [
    'SecurityEnforcement',
    'SecurityError',
    'initialize_security',
    'get_security_status',
    'validate_file_input',
    'secure_open',
    '_security'  # For advanced usage
]
