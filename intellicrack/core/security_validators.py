"""
Comprehensive Security Validators

Production-ready security validation framework for Intellicrack operations.
Provides input validation, safe execution contexts, and security enforcement.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import ctypes
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationError(Exception):
    """Security validation error"""
    pass


class InputValidator:
    """Comprehensive input validation for security research tools"""
    
    # Dangerous patterns that should be blocked
    DANGEROUS_PATTERNS = [
        r'rm\s+-rf\s+/',
        r'format\s+c:',
        r'del\s+/[qs]\s+\\',
        r'shutdown\s+',
        r'reboot\s+',
        r'halt\s+',
        r'poweroff\s+',
        r'init\s+0',
        r'telinit\s+0',
        r'dd\s+if=/dev/zero\s+of=/',
        r'mkfs\.',
        r'fdisk\s+',
        r'parted\s+',
        r'systemctl\s+stop',
        r'service\s+\w+\s+stop',
        r'kill\s+-9\s+1',
        r'killall\s+-9',
        r':\s*:\s*:\s*:\s*:\s*:',  # Fork bomb pattern
        r'\|\s*\|\s*\|\s*\|',     # Multiple pipe chains
    ]
    
    # Safe file extensions for analysis
    SAFE_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.bin', '.elf', '.so', '.dylib', '.app',
        '.msi', '.msp', '.cab', '.zip', '.7z', '.rar', '.tar', '.gz',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
        '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
        '.txt', '.log', '.xml', '.json', '.yaml', '.yml', '.ini', '.cfg'
    }
    
    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        SecurityLevel.LOW: 100 * 1024 * 1024,      # 100MB
        SecurityLevel.MEDIUM: 500 * 1024 * 1024,   # 500MB
        SecurityLevel.HIGH: 1024 * 1024 * 1024,    # 1GB
        SecurityLevel.CRITICAL: 10 * 1024 * 1024 * 1024  # 10GB
    }
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.max_file_size = self.MAX_FILE_SIZES[security_level]
    
    def validate_file_path(self, file_path: Union[str, Path]) -> bool:
        """Validate file path for security"""
        try:
            path = Path(file_path).resolve()
            
            # Check if path exists
            if not path.exists():
                raise ValidationError(f"File does not exist: {path}")
            
            # Check if it's actually a file
            if not path.is_file():
                raise ValidationError(f"Path is not a file: {path}")
            
            # Check file size
            file_size = path.stat().st_size
            if file_size > self.max_file_size:
                raise ValidationError(
                    f"File too large: {file_size} bytes (max: {self.max_file_size})"
                )
            
            # Check file extension
            if path.suffix.lower() not in self.SAFE_EXTENSIONS:
                logger.warning(f"Potentially unsafe file extension: {path.suffix}")
            
            # Check for path traversal attempts
            str_path = str(path)
            if '..' in str_path or '~' in str_path:
                raise ValidationError(f"Path traversal detected: {str_path}")
            
            # Ensure file is readable
            if not os.access(path, os.R_OK):
                raise ValidationError(f"File not readable: {path}")
            
            return True
            
        except Exception as e:
            logger.error(f"File path validation failed: {e}")
            raise ValidationError(f"Invalid file path: {e}")
    
    def validate_command_input(self, command: str, allowed_commands: Optional[Set[str]] = None) -> bool:
        """Validate command input for dangerous patterns"""
        try:
            # Check for dangerous patterns
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    raise ValidationError(f"Dangerous command pattern detected: {pattern}")
            
            # Check against allowed commands if provided
            if allowed_commands:
                command_parts = command.split()
                if command_parts and command_parts[0] not in allowed_commands:
                    raise ValidationError(f"Command not in allowed list: {command_parts[0]}")
            
            # Check for shell injection attempts
            dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']']
            if any(char in command for char in dangerous_chars):
                logger.warning(f"Potentially dangerous characters in command: {command}")
            
            # Limit command length
            if len(command) > 2048:
                raise ValidationError("Command too long")
            
            return True
            
        except Exception as e:
            logger.error(f"Command validation failed: {e}")
            raise ValidationError(f"Invalid command: {e}")
    
    def validate_network_address(self, address: str) -> bool:
        """Validate network address"""
        try:
            # Check for localhost/loopback only in research context
            if self.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                if not (address.startswith('127.') or address == 'localhost'):
                    raise ValidationError("Only localhost connections allowed at this security level")
            
            # Basic IP validation (simplified)
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', address):
                parts = address.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    return True
            
            # Hostname validation
            if re.match(r'^[a-zA-Z0-9.-]+$', address) and len(address) <= 253:
                return True
            
            raise ValidationError(f"Invalid network address: {address}")
            
        except Exception as e:
            logger.error(f"Network address validation failed: {e}")
            raise ValidationError(f"Invalid network address: {e}")
    
    def validate_memory_address(self, address: int, size: int) -> bool:
        """Validate memory address and size for safety"""
        try:
            # Check for null pointer
            if address == 0:
                raise ValidationError("Null pointer access")
            
            # Check for reasonable address ranges (x64)
            if address < 0x10000 or address > 0x7FFFFFFFFFFF:
                raise ValidationError(f"Address outside valid range: 0x{address:016X}")
            
            # Check size limits
            max_size = 100 * 1024 * 1024  # 100MB max allocation
            if size <= 0 or size > max_size:
                raise ValidationError(f"Invalid memory size: {size}")
            
            # Check for integer overflow
            if address + size < address:
                raise ValidationError("Integer overflow in address calculation")
            
            return True
            
        except Exception as e:
            logger.error(f"Memory address validation failed: {e}")
            raise ValidationError(f"Invalid memory address: {e}")


class SafeExecutionContext:
    """Safe execution context for security research operations"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.temp_dir = None
        self.created_files = []
        self.allocated_memory = []
    
    def __enter__(self):
        """Enter safe execution context"""
        try:
            # Create temporary directory for safe operations
            self.temp_dir = tempfile.mkdtemp(prefix='intellicrack_safe_')
            logger.info(f"Created safe execution context: {self.temp_dir}")
            return self
            
        except Exception as e:
            logger.error(f"Failed to create safe execution context: {e}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit safe execution context and cleanup"""
        try:
            self.cleanup()
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    def cleanup(self):
        """Clean up resources"""
        try:
            # Clean up created files
            for file_path in self.created_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except Exception as e:
                    logger.warning(f"Failed to remove file {file_path}: {e}")
            
            # Clean up temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            
            # Clean up allocated memory
            for mem_info in self.allocated_memory:
                try:
                    if os.name == 'nt':  # Windows
                        ctypes.windll.kernel32.VirtualFree(
                            mem_info['address'], 0, 0x8000  # MEM_RELEASE
                        )
                except Exception as e:
                    logger.warning(f"Failed to free memory: {e}")
            
            logger.info("Safe execution context cleaned up")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def create_temp_file(self, content: bytes, extension: str = '.bin') -> Path:
        """Create temporary file safely"""
        try:
            if not self.temp_dir:
                raise ValidationError("Safe execution context not initialized")
            
            # Validate extension
            if extension not in InputValidator.SAFE_EXTENSIONS:
                logger.warning(f"Potentially unsafe extension: {extension}")
            
            # Create temporary file
            fd, temp_path = tempfile.mkstemp(suffix=extension, dir=self.temp_dir)
            
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(content)
                
                self.created_files.append(temp_path)
                logger.debug(f"Created temporary file: {temp_path}")
                return Path(temp_path)
                
            except Exception:
                os.close(fd)
                raise
                
        except Exception as e:
            logger.error(f"Failed to create temporary file: {e}")
            raise ValidationError(f"Temporary file creation failed: {e}")
    
    def safe_subprocess_run(self, command: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run subprocess safely with timeout and validation"""
        try:
            # Validate command
            validator = InputValidator(self.security_level)
            validator.validate_command_input(' '.join(command))
            
            # Set working directory to temp dir for safety
            cwd = self.temp_dir if self.temp_dir else os.getcwd()
            
            # Run with timeout and security restrictions
            result = subprocess.run(
                command,
                cwd=cwd,
                timeout=timeout,
                capture_output=True,
                text=True,
                check=False
            )
            
            logger.debug(f"Command executed: {' '.join(command)}")
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            raise ValidationError("Command execution timeout")
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise ValidationError(f"Safe subprocess execution failed: {e}")


class SecurityEnforcer:
    """Central security enforcement for Intellicrack operations"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.validator = InputValidator(security_level)
        self.audit_log = []
    
    def audit_operation(self, operation: str, details: Dict[str, Any], result: str):
        """Audit security-relevant operations"""
        audit_entry = {
            'timestamp': __import__('time').time(),
            'operation': operation,
            'details': details,
            'result': result,
            'security_level': self.security_level.value
        }
        
        self.audit_log.append(audit_entry)
        logger.info(f"Audited operation: {operation} - {result}")
    
    def validate_binary_analysis(self, file_path: Union[str, Path]) -> bool:
        """Validate binary analysis operation"""
        try:
            self.validator.validate_file_path(file_path)
            
            # Additional binary-specific validation
            path = Path(file_path)
            
            # Check file signature/magic bytes
            with open(path, 'rb') as f:
                header = f.read(4)
                
            # PE files
            if header[:2] == b'MZ':
                logger.debug("Detected PE file")
            # ELF files
            elif header[:4] == b'\x7fELF':
                logger.debug("Detected ELF file")
            # Mach-O files
            elif header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
                logger.debug("Detected Mach-O file")
            else:
                logger.warning(f"Unknown file format: {header.hex()}")
            
            self.audit_operation(
                'binary_analysis',
                {'file_path': str(path), 'file_size': path.stat().st_size},
                'validated'
            )
            
            return True
            
        except Exception as e:
            self.audit_operation(
                'binary_analysis',
                {'file_path': str(file_path), 'error': str(e)},
                'rejected'
            )
            raise
    
    def validate_exploitation_operation(self, operation_type: str, parameters: Dict[str, Any]) -> bool:
        """Validate exploitation research operation"""
        try:
            # Check if operation is allowed at current security level
            allowed_operations = {
                SecurityLevel.LOW: {'analysis', 'static_analysis'},
                SecurityLevel.MEDIUM: {'analysis', 'static_analysis', 'controlled_testing'},
                SecurityLevel.HIGH: {'analysis', 'static_analysis', 'controlled_testing', 'safe_exploitation'},
                SecurityLevel.CRITICAL: {'analysis', 'static_analysis', 'controlled_testing', 'safe_exploitation', 'advanced_research'}
            }
            
            if operation_type not in allowed_operations[self.security_level]:
                raise ValidationError(f"Operation {operation_type} not allowed at security level {self.security_level}")
            
            # Validate target restrictions
            if 'target' in parameters:
                if self.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                    # Only allow localhost targets for high security
                    self.validator.validate_network_address(parameters['target'])
            
            # Validate payload restrictions
            if 'payload' in parameters:
                payload = parameters['payload']
                if isinstance(payload, (str, bytes)):
                    # Check for destructive patterns
                    payload_str = payload if isinstance(payload, str) else payload.decode('utf-8', errors='ignore')
                    self.validator.validate_command_input(payload_str)
            
            self.audit_operation(
                'exploitation_operation',
                {'operation_type': operation_type, 'parameters': parameters},
                'validated'
            )
            
            return True
            
        except Exception as e:
            self.audit_operation(
                'exploitation_operation',
                {'operation_type': operation_type, 'error': str(e)},
                'rejected'
            )
            raise
    
    def get_audit_report(self) -> Dict[str, Any]:
        """Get security audit report"""
        return {
            'security_level': self.security_level.value,
            'total_operations': len(self.audit_log),
            'validated_operations': len([entry for entry in self.audit_log if entry['result'] == 'validated']),
            'rejected_operations': len([entry for entry in self.audit_log if entry['result'] == 'rejected']),
            'recent_operations': self.audit_log[-10:] if self.audit_log else []
        }