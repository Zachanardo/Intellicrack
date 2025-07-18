"""
Security utilities for Intellicrack
Provides secure alternatives to common operations
"""

import hashlib
import json
import shlex
import subprocess
from typing import Any, List, Optional, Union

import yaml


class SecurityError(Exception):
    """Raised when a security policy is violated"""
    pass

def secure_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """
    Generate a secure hash of the given data
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha512, etc.)
    
    Returns:
        Hex digest of the hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    if algorithm == 'md5':
        # MD5 only for non-security purposes
        return hashlib.md5(data, usedforsecurity=False).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def secure_subprocess(command: Union[str, List[str]],
                     shell: bool = False,
                     timeout: Optional[int] = 30,
                     **kwargs) -> subprocess.CompletedProcess:
    """
    Execute a subprocess command securely
    
    Args:
        command: Command to execute
        shell: Whether to use shell (discouraged)
        timeout: Command timeout in seconds
        **kwargs: Additional arguments for subprocess.run
    
    Returns:
        CompletedProcess instance
    
    Raises:
        SecurityError: If shell=True without whitelist
    """
    if shell:
        raise SecurityError(
            "shell=True is not allowed for security reasons. "
            "Use a list of arguments instead."
        )

    if isinstance(command, str):
        # Parse command string into list safely
        command = shlex.split(command)

    return subprocess.run(
        command,
        shell=False,
        timeout=timeout,
        capture_output=True,
        text=True,
        **kwargs
    )

def secure_yaml_load(data: str) -> Any:
    """
    Safely load YAML data
    
    Args:
        data: YAML string to parse
    
    Returns:
        Parsed YAML data
    """
    return yaml.safe_load(data)

def secure_json_load(data: str) -> Any:
    """
    Safely load JSON data
    
    Args:
        data: JSON string to parse
    
    Returns:
        Parsed JSON data
    """
    return json.loads(data)

def validate_file_path(path: str, allowed_extensions: Optional[List[str]] = None) -> bool:
    """
    Validate a file path for security
    
    Args:
        path: File path to validate
        allowed_extensions: List of allowed file extensions
    
    Returns:
        True if path is valid
    
    Raises:
        SecurityError: If path is invalid or insecure
    """
    import os

    # Prevent path traversal
    if '..' in path or path.startswith('/'):
        raise SecurityError(f"Potentially malicious path: {path}")

    # Check file extension
    if allowed_extensions:
        ext = os.path.splitext(path)[1].lower()
        if ext not in allowed_extensions:
            raise SecurityError(f"File extension not allowed: {ext}")

    return True

def sanitize_input(text: str, max_length: int = 1024) -> str:
    """
    Sanitize user input
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized text
    """
    # Remove null bytes
    text = text.replace('\x00', '')

    # Limit length
    text = text[:max_length]

    # Remove control characters
    import re
    text = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', text)

    return text.strip()
