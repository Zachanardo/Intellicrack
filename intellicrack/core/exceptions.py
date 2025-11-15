"""Intellicrack Custom Exceptions.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


class IntellicrackError(Exception):
    """Base exception for all Intellicrack-specific errors."""



class ConfigurationError(IntellicrackError):
    """Raised when configuration is missing, invalid, or incomplete."""

    def __init__(self, message: str, service_name: str | None = None, config_key: str | None = None) -> None:
        """Initialize configuration error.

        Args:
            message: Error message
            service_name: Name of the service with configuration issue
            config_key: Configuration key that caused the error

        """
        super().__init__(message)
        self.service_name = service_name
        self.config_key = config_key


class ServiceUnavailableError(IntellicrackError):
    """Raised when a required service is unavailable."""

    def __init__(self, message: str, service_name: str, url: str | None = None) -> None:
        """Initialize service unavailable error.

        Args:
            message: Error message
            service_name: Name of the unavailable service
            url: URL that was unreachable

        """
        super().__init__(message)
        self.service_name = service_name
        self.url = url


class ToolNotFoundError(IntellicrackError):
    """Raised when a required tool is not found or configured."""

    def __init__(self, message: str, tool_name: str, search_paths: list[str] | None = None) -> None:
        """Initialize tool not found error.

        Args:
            message: Error message
            tool_name: Name of the missing tool
            search_paths: Paths that were searched

        """
        super().__init__(message)
        self.tool_name = tool_name
        self.search_paths = search_paths or []


class ValidationError(IntellicrackError):
    """Raised when data validation fails."""

    def __init__(self, message: str, field_name: str | None = None, value: str | None = None) -> None:
        """Initialize validation error.

        Args:
            message: Error message
            field_name: Name of the field that failed validation
            value: Value that failed validation

        """
        super().__init__(message)
        self.field_name = field_name
        self.value = value


class SecurityError(IntellicrackError):
    """Raised when security validation fails."""



class AnalysisError(IntellicrackError):
    """Raised when binary analysis fails."""

    def __init__(self, message: str, binary_path: str | None = None, analysis_type: str | None = None) -> None:
        """Initialize analysis error.

        Args:
            message: Error message
            binary_path: Path to binary that failed analysis
            analysis_type: Type of analysis that failed

        """
        super().__init__(message)
        self.binary_path = binary_path
        self.analysis_type = analysis_type


class ExploitationError(IntellicrackError):
    """Raised when exploitation operations fail."""

    def __init__(self, message: str, target: str | None = None, technique: str | None = None) -> None:
        """Initialize exploitation error.

        Args:
            message: Error message
            target: Target that failed exploitation
            technique: Exploitation technique that failed

        """
        super().__init__(message)
        self.target = target
        self.technique = technique


class NetworkError(IntellicrackError):
    """Raised when network operations fail."""

    def __init__(self, message: str, host: str | None = None, port: int | None = None) -> None:
        """Initialize network error.

        Args:
            message: Error message
            host: Host that failed connection
            port: Port that failed connection

        """
        super().__init__(message)
        self.host = host
        self.port = port
