"""
Configuration Validation Utilities for Intellicrack

Provides custom validators and validation utilities for configuration validation,
including path validation, version constraints, and system requirement checks.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import ValidationError


class ValidationResult:
    """Result of a validation check."""
    
    def __init__(self, is_valid: bool, message: str = "", warnings: List[str] = None):
        self.is_valid = is_valid
        self.message = message
        self.warnings = warnings or []
    
    def __bool__(self) -> bool:
        return self.is_valid
    
    def __str__(self) -> str:
        return self.message


class PathValidator:
    """Validates file and directory paths."""
    
    @staticmethod
    def validate_directory(path: Union[str, Path], create_if_missing: bool = False) -> ValidationResult:
        """
        Validate that a directory exists and is accessible.
        
        Args:
            path: Directory path to validate
            create_if_missing: Whether to create the directory if it doesn't exist
            
        Returns:
            ValidationResult indicating success/failure
        """
        try:
            path_obj = Path(path).expanduser().resolve()
            
            if not path_obj.exists():
                if create_if_missing:
                    try:
                        path_obj.mkdir(parents=True, exist_ok=True)
                        return ValidationResult(True, f"Created directory: {path_obj}")
                    except OSError as e:
                        return ValidationResult(False, f"Cannot create directory {path_obj}: {e}")
                else:
                    return ValidationResult(False, f"Directory does not exist: {path_obj}")
            
            if not path_obj.is_dir():
                return ValidationResult(False, f"Path is not a directory: {path_obj}")
            
            # Check if directory is writable
            if not os.access(path_obj, os.W_OK):
                return ValidationResult(True, f"Directory exists: {path_obj}", 
                                      ["Directory is not writable"])
            
            return ValidationResult(True, f"Directory is valid: {path_obj}")
            
        except Exception as e:
            return ValidationResult(False, f"Error validating directory {path}: {e}")
    
    @staticmethod
    def validate_file(path: Union[str, Path], must_exist: bool = True) -> ValidationResult:
        """
        Validate that a file exists and is accessible.
        
        Args:
            path: File path to validate
            must_exist: Whether the file must exist
            
        Returns:
            ValidationResult indicating success/failure
        """
        try:
            path_obj = Path(path).expanduser().resolve()
            
            if not path_obj.exists():
                if must_exist:
                    return ValidationResult(False, f"File does not exist: {path_obj}")
                else:
                    # Check if parent directory exists and is writable
                    parent = path_obj.parent
                    if not parent.exists():
                        return ValidationResult(False, f"Parent directory does not exist: {parent}")
                    if not os.access(parent, os.W_OK):
                        return ValidationResult(False, f"Parent directory is not writable: {parent}")
                    return ValidationResult(True, f"File path is valid: {path_obj}")
            
            if not path_obj.is_file():
                return ValidationResult(False, f"Path is not a file: {path_obj}")
            
            # Check if file is readable
            if not os.access(path_obj, os.R_OK):
                return ValidationResult(False, f"File is not readable: {path_obj}")
            
            return ValidationResult(True, f"File is valid: {path_obj}")
            
        except Exception as e:
            return ValidationResult(False, f"Error validating file {path}: {e}")
    
    @staticmethod
    def validate_executable(path: Union[str, Path]) -> ValidationResult:
        """
        Validate that a file is executable.
        
        Args:
            path: Executable path to validate
            
        Returns:
            ValidationResult indicating success/failure
        """
        # First validate as file
        file_result = PathValidator.validate_file(path, must_exist=True)
        if not file_result:
            return file_result
        
        try:
            path_obj = Path(path).expanduser().resolve()
            
            # Check if file is executable
            if not os.access(path_obj, os.X_OK):
                return ValidationResult(False, f"File is not executable: {path_obj}")
            
            return ValidationResult(True, f"Executable is valid: {path_obj}")
            
        except Exception as e:
            return ValidationResult(False, f"Error validating executable {path}: {e}")


class VersionValidator:
    """Validates version strings and constraints."""
    
    VERSION_PATTERN = re.compile(r'^(\d+)\.(\d+)\.(\d+)(?:[-.](\w+))?$')
    
    @staticmethod
    def parse_version(version_str: str) -> Optional[Tuple[int, int, int, str]]:
        """
        Parse version string into components.
        
        Args:
            version_str: Version string (e.g., "1.2.3", "2.0.0-beta")
            
        Returns:
            Tuple of (major, minor, patch, suffix) or None if invalid
        """
        if not version_str:
            return None
        
        match = VersionValidator.VERSION_PATTERN.match(version_str.strip())
        if not match:
            return None
        
        major, minor, patch, suffix = match.groups()
        return (int(major), int(minor), int(patch), suffix or "")
    
    @staticmethod
    def compare_versions(version1: str, version2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            version1: First version string
            version2: Second version string
            
        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        v1_parts = VersionValidator.parse_version(version1)
        v2_parts = VersionValidator.parse_version(version2)
        
        if v1_parts is None or v2_parts is None:
            return 0  # Cannot compare invalid versions
        
        # Compare major.minor.patch
        for i in range(3):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
        
        # Compare suffix (empty string is "greater" than any suffix)
        suffix1, suffix2 = v1_parts[3], v2_parts[3]
        if suffix1 == suffix2:
            return 0
        elif suffix1 == "":
            return 1  # Release version > pre-release
        elif suffix2 == "":
            return -1  # Pre-release < release version
        else:
            return -1 if suffix1 < suffix2 else 1
    
    @staticmethod
    def validate_version_constraint(version: str, constraint: str) -> ValidationResult:
        """
        Validate that a version meets a constraint.
        
        Args:
            version: Version to check
            constraint: Version constraint (e.g., ">=1.0.0", "~2.1.0")
            
        Returns:
            ValidationResult indicating success/failure
        """
        if not version or not constraint:
            return ValidationResult(False, "Version or constraint is empty")
        
        # Parse constraint
        constraint = constraint.strip()
        if constraint.startswith(">="):
            required_version = constraint[2:].strip()
            comparison = VersionValidator.compare_versions(version, required_version)
            if comparison >= 0:
                return ValidationResult(True, f"Version {version} meets constraint {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not meet constraint {constraint}")
        
        elif constraint.startswith("<="):
            required_version = constraint[2:].strip()
            comparison = VersionValidator.compare_versions(version, required_version)
            if comparison <= 0:
                return ValidationResult(True, f"Version {version} meets constraint {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not meet constraint {constraint}")
        
        elif constraint.startswith(">"):
            required_version = constraint[1:].strip()
            comparison = VersionValidator.compare_versions(version, required_version)
            if comparison > 0:
                return ValidationResult(True, f"Version {version} meets constraint {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not meet constraint {constraint}")
        
        elif constraint.startswith("<"):
            required_version = constraint[1:].strip()
            comparison = VersionValidator.compare_versions(version, required_version)
            if comparison < 0:
                return ValidationResult(True, f"Version {version} meets constraint {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not meet constraint {constraint}")
        
        elif constraint.startswith("==") or constraint.startswith("="):
            required_version = constraint.lstrip("=").strip()
            comparison = VersionValidator.compare_versions(version, required_version)
            if comparison == 0:
                return ValidationResult(True, f"Version {version} meets constraint {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not meet constraint {constraint}")
        
        else:
            # Assume exact match
            comparison = VersionValidator.compare_versions(version, constraint)
            if comparison == 0:
                return ValidationResult(True, f"Version {version} matches {constraint}")
            else:
                return ValidationResult(False, f"Version {version} does not match {constraint}")


class SystemValidator:
    """Validates system requirements and capabilities."""
    
    @staticmethod
    def validate_memory_requirement(required_memory: str) -> ValidationResult:
        """
        Validate that system has sufficient memory.
        
        Args:
            required_memory: Required memory (e.g., "2GB", "512MB")
            
        Returns:
            ValidationResult indicating success/failure
        """
        try:
            from .config_models import parse_memory_size
            required_bytes = parse_memory_size(required_memory)
            
            # Get system memory
            try:
                import psutil
                available_bytes = psutil.virtual_memory().available
                total_bytes = psutil.virtual_memory().total
                
                if available_bytes >= required_bytes:
                    return ValidationResult(True, 
                        f"Sufficient memory available: {available_bytes // (1024**3):.1f}GB of {total_bytes // (1024**3):.1f}GB")
                else:
                    return ValidationResult(False,
                        f"Insufficient memory: {required_memory} required, only {available_bytes // (1024**3):.1f}GB available")
            
            except ImportError:
                return ValidationResult(True, 
                    f"Cannot check system memory (psutil not available), assuming {required_memory} is available",
                    ["Install psutil for accurate memory validation"])
        
        except Exception as e:
            return ValidationResult(False, f"Error validating memory requirement: {e}")
    
    @staticmethod
    def validate_disk_space(path: Union[str, Path], required_space: str) -> ValidationResult:
        """
        Validate that sufficient disk space is available.
        
        Args:
            path: Path to check disk space for
            required_space: Required space (e.g., "1GB", "500MB")
            
        Returns:
            ValidationResult indicating success/failure
        """
        try:
            from .config_models import parse_memory_size
            required_bytes = parse_memory_size(required_space)
            
            path_obj = Path(path).expanduser().resolve()
            if not path_obj.exists():
                path_obj = path_obj.parent
            
            # Get disk space
            stat = shutil.disk_usage(path_obj)
            available_bytes = stat.free
            
            if available_bytes >= required_bytes:
                return ValidationResult(True,
                    f"Sufficient disk space: {available_bytes // (1024**3):.1f}GB available")
            else:
                return ValidationResult(False,
                    f"Insufficient disk space: {required_space} required, only {available_bytes // (1024**3):.1f}GB available")
        
        except Exception as e:
            return ValidationResult(False, f"Error validating disk space: {e}")
    
    @staticmethod
    def validate_network_connectivity(host: str = "8.8.8.8", port: int = 53, timeout: int = 5) -> ValidationResult:
        """
        Validate network connectivity.
        
        Args:
            host: Host to test connectivity to
            port: Port to test
            timeout: Connection timeout in seconds
            
        Returns:
            ValidationResult indicating success/failure
        """
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                result = sock.connect_ex((host, port))
                if result == 0:
                    return ValidationResult(True, f"Network connectivity confirmed to {host}:{port}")
                else:
                    return ValidationResult(False, f"Cannot connect to {host}:{port}")
            finally:
                sock.close()
        
        except Exception as e:
            return ValidationResult(False, f"Error testing network connectivity: {e}")


class ConfigurationValidator:
    """Comprehensive configuration validator."""
    
    def __init__(self):
        self.path_validator = PathValidator()
        self.version_validator = VersionValidator()
        self.system_validator = SystemValidator()
    
    def validate_configuration(self, config_dict: Dict[str, Any]) -> List[ValidationResult]:
        """
        Validate entire configuration dictionary.
        
        Args:
            config_dict: Configuration dictionary to validate
            
        Returns:
            List of validation results
        """
        results = []
        
        # Validate directories
        if 'directories' in config_dict:
            results.extend(self._validate_directories(config_dict['directories']))
        
        # Validate tools
        if 'tools' in config_dict:
            results.extend(self._validate_tools(config_dict['tools']))
        
        # Validate system requirements
        if 'analysis' in config_dict:
            results.extend(self._validate_analysis_config(config_dict['analysis']))
        
        # Validate network configuration
        if 'network' in config_dict:
            results.extend(self._validate_network_config(config_dict['network']))
        
        return results
    
    def _validate_directories(self, directories: Dict[str, Any]) -> List[ValidationResult]:
        """Validate directory configuration."""
        results = []
        
        for dir_name, dir_path in directories.items():
            if dir_path:
                result = self.path_validator.validate_directory(dir_path, create_if_missing=True)
                results.append(result)
        
        return results
    
    def _validate_tools(self, tools: Dict[str, Any]) -> List[ValidationResult]:
        """Validate tool configuration."""
        results = []
        
        for tool_name, tool_config in tools.items():
            if isinstance(tool_config, dict) and tool_config.get('available'):
                tool_path = tool_config.get('path')
                if tool_path:
                    result = self.path_validator.validate_executable(tool_path)
                    results.append(result)
                
                # Validate version constraints
                version = tool_config.get('version')
                required_version = tool_config.get('required_version')
                if version and required_version:
                    constraint = f">={required_version}"
                    result = self.version_validator.validate_version_constraint(version, constraint)
                    results.append(result)
        
        return results
    
    def _validate_analysis_config(self, analysis: Dict[str, Any]) -> List[ValidationResult]:
        """Validate analysis configuration."""
        results = []
        
        # Validate memory requirements
        max_memory = analysis.get('max_memory_usage')
        if max_memory:
            result = self.system_validator.validate_memory_requirement(max_memory)
            results.append(result)
        
        return results
    
    def _validate_network_config(self, network: Dict[str, Any]) -> List[ValidationResult]:
        """Validate network configuration."""
        results = []
        
        # Test network connectivity if proxy is configured
        if network.get('proxy_enabled'):
            proxy_host = network.get('proxy_host')
            proxy_port = network.get('proxy_port', 8080)
            
            if proxy_host:
                # Remove protocol prefix if present
                host = proxy_host.replace('http://', '').replace('https://', '')
                result = self.system_validator.validate_network_connectivity(host, proxy_port)
                results.append(result)
        
        return results


def validate_pydantic_errors(validation_error: ValidationError) -> List[str]:
    """
    Convert Pydantic validation errors to user-friendly messages.
    
    Args:
        validation_error: Pydantic ValidationError
        
    Returns:
        List of user-friendly error messages
    """
    messages = []
    
    for error in validation_error.errors():
        location = " -> ".join(str(loc) for loc in error['loc'])
        error_type = error['type']
        message = error['msg']
        
        if error_type == 'missing':
            messages.append(f"Missing required field: {location}")
        elif error_type == 'type_error':
            messages.append(f"Invalid type for {location}: {message}")
        elif error_type == 'value_error':
            messages.append(f"Invalid value for {location}: {message}")
        elif error_type == 'assertion_error':
            messages.append(f"Validation failed for {location}: {message}")
        else:
            messages.append(f"Error in {location}: {message}")
    
    return messages


def create_validation_summary(results: List[ValidationResult]) -> Dict[str, Any]:
    """
    Create a summary of validation results.
    
    Args:
        results: List of validation results
        
    Returns:
        Summary dictionary with counts and messages
    """
    total = len(results)
    passed = sum(1 for r in results if r.is_valid)
    failed = total - passed
    
    warnings = []
    errors = []
    
    for result in results:
        if result.warnings:
            warnings.extend(result.warnings)
        if not result.is_valid:
            errors.append(result.message)
    
    return {
        'total_checks': total,
        'passed': passed,
        'failed': failed,
        'warnings': warnings,
        'errors': errors,
        'success_rate': (passed / total * 100) if total > 0 else 0
    }