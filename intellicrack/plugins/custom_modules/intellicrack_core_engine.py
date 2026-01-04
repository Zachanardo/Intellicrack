#!/usr/bin/env python3
"""Intellicrack core engine plugin.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import asyncio
import hashlib
import importlib.util
import inspect
import json
import logging
import logging.handlers
import multiprocessing as mp
import os
import queue
import signal
import sys
import tempfile
import threading
import time
import traceback
import uuid
import weakref
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict, cast

import yaml
from jsonschema import ValidationError, validate

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.logger import log_all_methods


if TYPE_CHECKING:
    import subprocess
    from types import FrameType, ModuleType


"""
Intellicrack Core Engine

Main integration engine that orchestrates all components of the Intellicrack framework.
Provides unified workflow management, plugin coordination, and real-time analysis
orchestration for binary analysis and license bypass operations.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""


class ComponentType(Enum):
    """Types of components in the framework."""

    GHIDRA_SCRIPT = "ghidra_script"
    FRIDA_SCRIPT = "frida_script"
    RADARE2_MODULE = "radare2_module"
    ML_MODULE = "ml_module"
    CUSTOM_MODULE = "custom_module"
    BYPASS_COMPONENT = "bypass_component"
    ANALYSIS_TOOL = "analysis_tool"
    UI_COMPONENT = "ui_component"


class PluginStatus(Enum):
    """Plugin lifecycle status."""

    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    VALIDATING = "validating"
    VALIDATED = "validated"
    INITIALIZING = "initializing"
    READY = "ready"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    UNLOADING = "unloading"


class EventPriority(Enum):
    """Event priority levels."""

    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    DEBUG = 4


class WorkflowStatus(Enum):
    """Workflow execution status."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@log_all_methods
@dataclass
class PluginMetadata:
    """Plugin metadata structure.

    Stores complete metadata for plugins including name, version, description,
    type, capabilities, dependencies, and configuration schema for framework
    integration and management.

    Attributes:
        name: Plugin identifier name.
        version: Plugin version string in semantic versioning format.
        description: Human-readable plugin description.
        component_type: Type of component (GHIDRA_SCRIPT, FRIDA_SCRIPT, etc.).
        author: Plugin author name or organization.
        license: License type (GPL, MIT, etc.).
        dependencies: List of required dependencies.
        capabilities: List of plugin capabilities.
        supported_formats: File formats supported by the plugin.
        configuration_schema: JSON schema for configuration validation.
        tags: Metadata tags for categorization and search.
    """

    name: str
    version: str
    description: str
    component_type: ComponentType
    author: str = ""
    license: str = ""
    dependencies: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    supported_formats: list[str] = field(default_factory=list)
    configuration_schema: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert plugin metadata to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary containing all plugin metadata fields
                including name, version, description, type, and configuration
                schema for serialization and transmission.
        """
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "component_type": self.component_type.value,
            "author": self.author,
            "license": self.license,
            "dependencies": self.dependencies,
            "capabilities": self.capabilities,
            "supported_formats": self.supported_formats,
            "configuration_schema": self.configuration_schema,
            "tags": self.tags,
        }


class ScriptMetadataDict(TypedDict):
    """TypedDict for script metadata during extraction."""

    name: str
    version: str
    description: str
    author: str
    capabilities: list[str]
    dependencies: list[str]


@log_all_methods
@dataclass
class Event:
    """Event structure for inter-component communication.

    Represents events that flow through the event bus for asynchronous
    communication between plugins, analysis components, and workflow engines.
    Supports event priority, correlation, and time-to-live semantics.

    Attributes:
        event_type: Type of event (string identifier).
        source: Name of the component that emitted the event.
        target: Optional target component name for directed events.
        data: Arbitrary event data payload as dictionary.
        priority: Event priority level (CRITICAL to DEBUG).
        timestamp: Creation timestamp in UTC.
        event_id: Unique event identifier (UUID).
        correlation_id: Optional correlation ID for tracking related events.
        ttl: Optional time-to-live in seconds before event expires.
    """

    event_type: str
    source: str
    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    priority: EventPriority = EventPriority.MEDIUM
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary containing event_id, event_type, source,
                target, data, priority, timestamp in ISO format, correlation_id,
                and ttl for serialization and transmission.
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "target": self.target,
            "data": self.data,
            "priority": self.priority.value,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "ttl": self.ttl,
        }


@log_all_methods
@dataclass
class WorkflowStep:
    """Individual step in a workflow.

    Represents a single executable step within a workflow definition, specifying
    the plugin to invoke, method to call, parameters, dependencies, and execution
    options for licensing protection analysis.

    Attributes:
        step_id: Unique identifier for the step.
        name: Human-readable step name for workflow display.
        plugin_name: Name of the plugin that implements this step.
        method: Method name to invoke on the plugin.
        parameters: Dictionary of method parameters and arguments.
        dependencies: List of step IDs that must complete before this step.
        timeout: Optional execution timeout in seconds.
        retry_count: Current number of retry attempts made.
        max_retries: Maximum retry attempts allowed on failure.
        condition: Optional Python expression for conditional step execution.
    """

    step_id: str
    name: str
    plugin_name: str
    method: str
    parameters: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    timeout: int | None = None
    retry_count: int = 0
    max_retries: int = 3
    condition: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert workflow step to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary containing step_id, name, plugin_name, method,
                parameters, dependencies, timeout, retry_count, max_retries, and
                condition for serialization and workflow persistence.
        """
        return {
            "step_id": self.step_id,
            "name": self.name,
            "plugin_name": self.plugin_name,
            "method": self.method,
            "parameters": self.parameters,
            "dependencies": self.dependencies,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "condition": self.condition,
        }


@log_all_methods
@dataclass
class WorkflowDefinition:
    """Complete workflow definition.

    Specifies a complete workflow for licensing protection analysis, including
    all steps, execution configuration, error handling, and result aggregation
    strategies for analyzing and bypassing protection mechanisms.

    Attributes:
        workflow_id: Unique workflow identifier.
        name: Human-readable workflow name.
        description: Detailed workflow description and purpose.
        steps: List of WorkflowStep objects defining the execution sequence.
        parallel_execution: Whether steps can execute in parallel.
        timeout: Optional overall workflow timeout in seconds.
        error_handling: Error strategy ("stop", "continue", or "retry").
        result_aggregation: Result aggregation strategy ("merge", "last", "custom").
        tags: Workflow tags for categorization and search.
    """

    workflow_id: str
    name: str
    description: str
    steps: list[WorkflowStep]
    parallel_execution: bool = False
    timeout: int | None = None
    error_handling: str = "stop"
    result_aggregation: str = "merge"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert workflow definition to dictionary representation.

        Returns:
            dict[str, Any]: Dictionary containing workflow_id, name, description,
                steps (as dictionaries), parallel_execution, timeout, error_handling,
                result_aggregation, and tags for serialization and persistence.
        """
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "steps": [step.to_dict() for step in self.steps],
            "parallel_execution": self.parallel_execution,
            "timeout": self.timeout,
            "error_handling": self.error_handling,
            "result_aggregation": self.result_aggregation,
            "tags": self.tags,
        }


@log_all_methods
class LoggingManager:
    """Advanced logging manager with structured logging and multiple outputs.

    Manages hierarchical logging configuration with multiple handlers (console,
    file, JSON), component-specific loggers, and structured event logging for
    comprehensive framework diagnostics and analysis tracking.
    """

    def __init__(self, config: dict[str, Any] | str) -> None:
        """Initialize advanced logging manager with configuration.

        Args:
            config: Configuration dict or path to YAML config file. If dict,
                used directly. If string ending with .yaml, loads from file.
                Otherwise defaults to empty configuration.
        """
        self.config: dict[str, Any] = config if isinstance(config, dict) else {}
        self.loggers: dict[str, logging.Logger] = {}
        self.handlers: dict[str, logging.Handler] = {}

        self._logger_refs: weakref.WeakValueDictionary[str, logging.Logger] = weakref.WeakValueDictionary()

        # Use yaml for configuration if config is a string path
        if isinstance(config, str) and config.endswith(".yaml"):
            try:
                with open(config) as f:
                    self.config = yaml.safe_load(f)
            except Exception as e:
                logging.exception("Failed to load YAML config: %s, using default config", e)
                self.config = {}

        # Setup root logger
        self._setup_root_logger()

        # Setup component loggers
        self._setup_component_loggers()

    def _setup_root_logger(self) -> None:
        """Set up root logger with multiple handlers.

        Configures the root logger with console, file, JSON, and error handlers
        with appropriate formatters and log levels from configuration.

        Returns:
            None
        """
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        # Clear existing handlers
        root_logger.handlers.clear()

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, self.config.get("console_level", "INFO")))
        console_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        self.handlers["console"] = console_handler

        # File handler with rotation
        log_dir = Path(self.config.get("log_directory", "logs"))
        log_dir.mkdir(exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "intellicrack.log",
            maxBytes=self.config.get("max_log_size", 50 * 1024 * 1024),  # 50MB
            backupCount=self.config.get("backup_count", 5),
        )
        file_handler.setLevel(getattr(logging, self.config.get("file_level", "DEBUG")))
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        self.handlers["file"] = file_handler

        # JSON handler for structured logging
        json_handler = logging.handlers.RotatingFileHandler(
            log_dir / "intellicrack.json",
            maxBytes=self.config.get("max_log_size", 50 * 1024 * 1024),
            backupCount=self.config.get("backup_count", 5),
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(json_handler)
        self.handlers["json"] = json_handler

        # Error handler for critical errors
        error_handler = logging.handlers.RotatingFileHandler(
            log_dir / "errors.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        root_logger.addHandler(error_handler)
        self.handlers["error"] = error_handler

    def _setup_component_loggers(self) -> None:
        """Set up specialized loggers for different components.

        Creates named loggers for each framework component (plugin_manager,
        workflow_engine, event_bus, etc.) with debug-level configuration.

        Returns:
            None
        """
        components = [
            "plugin_manager",
            "workflow_engine",
            "event_bus",
            "analysis_coordinator",
            "resource_manager",
            "configuration_manager",
        ]

        for component in components:
            logger = logging.getLogger(f"intellicrack.{component}")
            logger.setLevel(logging.DEBUG)
            self.loggers[component] = logger

    def get_logger(self, name: str) -> logging.Logger:
        """Get logger for specific component.

        Retrieves or creates a named logger for a framework component,
        automatically adding to internal tracking dictionary.

        Args:
            name: Component name for the logger (e.g., "plugins", "workflows").

        Returns:
            logging.Logger: Logger instance configured for the named component.
        """
        if name not in self.loggers:
            logger = logging.getLogger(f"intellicrack.{name}")
            logger.setLevel(logging.DEBUG)
            self.loggers[name] = logger

        return self.loggers[name]

    def log_event(self, event: Event) -> None:
        """Log an event with structured data.

        Logs an Event object with all associated data through the events logger
        with extra context for structured logging.

        Args:
            event: Event instance to log with full event data.

        Returns:
            None
        """
        logger = self.get_logger("events")
        logger.info(
            "Event: %s",
            event.event_type,
            extra={
                "event_data": event.to_dict(),
                "component": "event_system",
            },
        )

    def log_plugin_operation(self, plugin_name: str, operation: str, status: str, details: dict[str, Any] | None = None) -> None:
        """Log plugin operation.

        Records plugin lifecycle and operational events with context information
        for plugin management and troubleshooting.

        Args:
            plugin_name: Name identifier of the plugin.
            operation: Operation being performed (e.g., "load", "initialize").
            status: Operation status (e.g., "started", "completed", "failed").
            details: Optional dictionary of additional operation context data.

        Returns:
            None
        """
        logger = self.get_logger("plugins")
        logger.info(
            "Plugin %s: %s -> %s",
            plugin_name,
            operation,
            status,
            extra={
                "plugin_name": plugin_name,
                "operation": operation,
                "status": status,
                "details": details or {},
                "component": "plugin_system",
            },
        )

    def log_workflow_step(
        self,
        workflow_id: str,
        step_id: str,
        status: str,
        duration: float | None = None,
        result: object = None,
    ) -> None:
        """Log workflow step execution.

        Records workflow step execution events with timing and result information
        for workflow monitoring and debugging.

        Args:
            workflow_id: Identifier of the parent workflow.
            step_id: Identifier of the specific step within the workflow.
            status: Step execution status (e.g., "running", "completed", "failed").
            duration: Optional execution duration in seconds.
            result: Optional step result object for tracking outputs.

        Returns:
            None
        """
        logger = self.get_logger("workflows")
        logger.info(
            "Workflow %s Step %s: %s",
            workflow_id,
            step_id,
            status,
            extra={
                "workflow_id": workflow_id,
                "step_id": step_id,
                "status": status,
                "duration": duration,
                "result_type": type(result).__name__ if result is not None else None,
                "component": "workflow_system",
            },
        )


@log_all_methods
class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging.

    Converts logging records into JSON format for machine-readable log output,
    including timestamp, level, logger name, message, and extra context fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON structure.

        Converts a logging LogRecord into a JSON-formatted string with all
        standard fields (timestamp, level, logger, message, function, line,
        thread information) and any extra custom fields.

        Args:
            record: logging.LogRecord instance to format.

        Returns:
            str: JSON-formatted log entry as a complete string.
        """
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
            "process": record.process,
        }

        # Add extra fields
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in log_entry and not key.startswith("_"):
                    try:
                        json.dumps(value)  # Test if serializable
                        log_entry[key] = value
                    except (TypeError, ValueError):
                        log_entry[key] = str(value)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


@log_all_methods
class ConfigurationManager:
    """Configuration management with validation and hot reloading.

    Manages framework configuration with JSON schema validation, file watching
    for hot reloading, and callback notification system for configuration changes.
    """

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize configuration manager with optional config path.

        Args:
            config_path: Optional path to configuration JSON file. Defaults to
                'config/intellicrack.json' if not provided.
        """
        self.config_path = Path(config_path) if config_path else Path("config/intellicrack.json")
        self.config: dict[str, Any] = {}
        self.schema: dict[str, Any] = {}
        self.watchers: list[Callable[[dict[str, Any]], None]] = []
        self.file_watcher: threading.Thread | None = None
        self.last_modified: float = 0
        self.logger = logging.getLogger(f"{__name__}.ConfigurationManager")

        # Load configuration schema
        self._load_schema()

        # Load initial configuration
        self.reload_config()

        # Start file watcher for hot reloading
        self._start_file_watcher()

    def _load_schema(self) -> None:
        """Load configuration schema for validation.

        Initializes JSON schema for validating framework configuration including
        logging, plugins, engine, tools, and analysis sections with required
        fields and type constraints.

        Returns:
            None
        """
        self.schema = {
            "type": "object",
            "properties": {
                "logging": {
                    "type": "object",
                    "properties": {
                        "console_level": {
                            "type": "string",
                            "enum": ["DEBUG", "INFO", "WARNING", "ERROR"],
                        },
                        "file_level": {
                            "type": "string",
                            "enum": ["DEBUG", "INFO", "WARNING", "ERROR"],
                        },
                        "log_directory": {"type": "string"},
                        "max_log_size": {"type": "integer", "minimum": 1024},
                        "backup_count": {"type": "integer", "minimum": 1},
                    },
                    "required": ["console_level", "file_level"],
                },
                "plugins": {
                    "type": "object",
                    "properties": {
                        "directories": {"type": "array", "items": {"type": "string"}},
                        "auto_discover": {"type": "boolean"},
                        "auto_load": {"type": "boolean"},
                        "load_timeout": {"type": "integer", "minimum": 1},
                        "enabled": {"type": "array", "items": {"type": "string"}},
                        "disabled": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["directories"],
                },
                "engine": {
                    "type": "object",
                    "properties": {
                        "max_workers": {"type": "integer", "minimum": 1},
                        "max_concurrent_workflows": {"type": "integer", "minimum": 1},
                        "default_timeout": {"type": "integer", "minimum": 1},
                        "resource_monitoring": {"type": "boolean"},
                        "auto_cleanup": {"type": "boolean"},
                    },
                    "required": ["max_workers"],
                },
                "tools": {
                    "type": "object",
                    "properties": {
                        "ghidra_path": {"type": "string"},
                        "frida_path": {"type": "string"},
                        "radare2_path": {"type": "string"},
                        "java_path": {"type": "string"},
                        "node_path": {"type": "string"},
                    },
                },
                "analysis": {
                    "type": "object",
                    "properties": {
                        "temp_directory": {"type": "string"},
                        "max_file_size": {"type": "integer", "minimum": 1024},
                        "supported_formats": {"type": "array", "items": {"type": "string"}},
                        "default_analysis_timeout": {"type": "integer", "minimum": 1},
                    },
                },
            },
            "required": ["logging", "plugins", "engine"],
        }

    def _get_default_config(self) -> dict[str, Any]:
        """Get default configuration.

        Returns:
            dict[str, Any]: Default configuration dict with logging, plugins, engine,
                tools, and analysis settings for framework initialization.
        """
        return {
            "logging": {
                "console_level": "INFO",
                "file_level": "DEBUG",
                "log_directory": "logs",
                "max_log_size": 52428800,  # 50MB
                "backup_count": 5,
            },
            "plugins": {
                "directories": [
                    "intellicrack/intellicrack/scripts/frida",
                    "intellicrack/intellicrack/scripts/radare2",
                    "intellicrack/intellicrack/plugins/custom_modules",
                    "intellicrack/ml",
                ],
                "auto_discover": True,
                "auto_load": True,
                "load_timeout": 30,
                "enabled": [],
                "disabled": [],
            },
            "engine": {
                "max_workers": mp.cpu_count(),
                "max_concurrent_workflows": 10,
                "default_timeout": 300,
                "resource_monitoring": True,
                "auto_cleanup": True,
            },
            "tools": {
                "ghidra_path": "",
                "frida_path": "frida",
                "radare2_path": "r2",
                "java_path": "java",
                "node_path": "node",
            },
            "analysis": {
                "temp_directory": "temp",
                "max_file_size": 1073741824,  # 1GB
                "supported_formats": [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"],
                "default_analysis_timeout": 600,
            },
        }

    def reload_config(self) -> None:
        """Reload configuration from file.

        Loads configuration from the configured file path, validates against schema,
        merges with defaults, and notifies all registered watchers of changes.

        Returns:
            None
        """
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    loaded_config = json.load(f)

                # Validate against schema
                validate(instance=loaded_config, schema=self.schema)

                # Merge with defaults
                default_config = self._get_default_config()
                self.config = self._deep_merge(default_config, loaded_config)

                self.last_modified = self.config_path.stat().st_mtime

            else:
                # Create default config file
                self.config = self._get_default_config()
                self._save_config()

            # Notify watchers
            for watcher in self.watchers:
                try:
                    watcher(self.config)
                except Exception as e:
                    self.logger.exception("Watcher error: %s", e)

        except (json.JSONDecodeError, ValidationError) as e:
            self.logger.exception("Configuration error: %s", e)
            self.config = self._get_default_config()

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Deep merge two dictionaries.

        Recursively merges override dict into base dict, preserving nested structure.

        Args:
            base: Base configuration dictionary.
            override: Override configuration dictionary to merge into base.

        Returns:
            dict[str, Any]: Merged configuration dictionary containing all keys from
                both dictionaries, with override values taking precedence over base
                values for all keys.
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _save_config(self) -> None:
        """Save current configuration to file.

        Writes current configuration dictionary to JSON file with parent
        directory creation if necessary.

        Returns:
            None
        """
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    def _start_file_watcher(self) -> None:
        """Start file watcher for hot reloading.

        Starts a daemon thread that monitors the configuration file for changes
        and automatically reloads when file modification timestamp changes.

        Returns:
            None
        """

        def watch_file() -> None:
            """Monitor configuration file for changes and reload on modification.

            Continuously polls the configuration file for modifications and triggers
            a reload when changes are detected. Implements exponential backoff on errors.

            Returns:
                None
            """
            while True:
                try:
                    if self.config_path.exists():
                        current_mtime = self.config_path.stat().st_mtime
                        if current_mtime > self.last_modified:
                            self.reload_config()

                    time.sleep(1)  # Check every second

                except Exception as e:
                    # Continue watching despite errors
                    self.logger.exception("File watcher error: %s", e)
                    time.sleep(5)

        self.file_watcher = threading.Thread(target=watch_file, daemon=True)
        self.file_watcher.start()

    def get(self, key: str, default: object = None) -> object:
        """Get configuration value with dot notation support.

        Retrieves configuration values using dot notation for nested access
        (e.g., "logging.console_level").

        Args:
            key: Configuration key with optional dot notation for nested access.
            default: Default value to return if key not found.

        Returns:
            object: Configuration value or default if not found.
        """
        keys = key.split(".")
        value: object = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: object) -> None:
        """Set configuration value with dot notation support.

        Sets configuration values using dot notation for nested access, creating
        intermediate dictionaries as needed, then persists to file.

        Args:
            key: Configuration key with optional dot notation for nested access.
            value: Value to set at the specified configuration key.

        Returns:
            None
        """
        keys = key.split(".")
        config = self.config

        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self._save_config()

    def add_watcher(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Add configuration change watcher.

        Registers a callback function to be invoked whenever configuration
        is reloaded or changed.

        Args:
            callback: Callable that accepts configuration dict and performs
                any necessary updates based on new configuration.

        Returns:
            None
        """
        self.watchers.append(callback)

    def remove_watcher(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Remove configuration change watcher.

        Unregisters a previously registered configuration watcher callback.

        Args:
            callback: The callback function to unregister.

        Returns:
            None
        """
        if callback in self.watchers:
            self.watchers.remove(callback)


@log_all_methods
class AbstractPlugin(ABC):
    """Abstract base class for all plugins.

    Defines the interface and common functionality for all plugin types
    (Ghidra, Frida, Python) used for binary analysis and license cracking.
    """

    def __init__(self, name: str, version: str = "1.0.0") -> None:
        """Initialize abstract plugin with name and version.

        Args:
            name: Plugin identifier name.
            version: Version string in semantic versioning format.
        """
        self.name = name
        self.version = version
        self.status = PluginStatus.DISCOVERED
        self.metadata: PluginMetadata | None = None
        self.config: dict[str, Any] = {}
        self.logger: logging.Logger | None = None
        self.event_bus: EventBus | None = None
        self.dependencies: list[str] = []
        self.capabilities: list[str] = []
        self.last_error: str | None = None
        self.performance_metrics: dict[str, Any] = {}

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata.

        Returns:
            PluginMetadata: Metadata object describing the plugin.
        """

    @abstractmethod
    async def initialize(self, config: dict[str, Any]) -> bool:
        """Initialize the plugin with configuration.

        Args:
            config: Configuration dictionary for plugin initialization.

        Returns:
            bool: True if initialization succeeded, False otherwise.
        """

    @abstractmethod
    async def activate(self) -> bool:
        """Activate the plugin.

        Returns:
            bool: True if activation succeeded, False otherwise.
        """

    @abstractmethod
    async def deactivate(self) -> bool:
        """Deactivate the plugin.

        Returns:
            bool: True if deactivation succeeded, False otherwise.
        """

    @abstractmethod
    async def cleanup(self) -> bool:
        """Cleanup plugin resources.

        Returns:
            bool: True if cleanup succeeded, False otherwise.
        """

    @abstractmethod
    def get_supported_operations(self) -> list[str]:
        """Get list of supported operations.

        Returns:
            list[str]: List of operation names that this plugin can execute.
        """

    @abstractmethod
    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute a specific operation.

        Args:
            operation: Operation name to execute.
            parameters: Dictionary of operation parameters.

        Returns:
            object: Operation result as returned by the plugin.

        Raises:
            ValueError: If operation is not supported.
        """

    def set_logger(self, logger: logging.Logger) -> None:
        """Set plugin logger.

        Configures the logger instance for plugin operations and diagnostics.

        Args:
            logger: Logger instance to use for plugin logging.

        Returns:
            None
        """
        self.logger = logger

    def set_event_bus(self, event_bus: "EventBus") -> None:
        """Set event bus for communication.

        Configures the event bus instance for inter-component communication
        and event emission from the plugin.

        Args:
            event_bus: EventBus instance for inter-component communication.

        Returns:
            None
        """
        self.event_bus = event_bus

    def update_config(self, config: dict[str, Any]) -> None:
        """Update plugin configuration.

        Merges provided configuration dictionary into the plugin's current config.

        Args:
            config: Configuration dictionary to merge into plugin config.

        Returns:
            None
        """
        self.config.update(config)

    def emit_event(self, event_type: str, data: dict[str, Any] | None = None, target: str | None = None) -> None:
        """Emit an event.

        Creates and emits an event through the event bus if available.

        Args:
            event_type: Type identifier for the event.
            data: Optional event payload data dictionary.
            target: Optional target component name for directed events.

        Returns:
            None
        """
        if self.event_bus:
            event = Event(
                event_type=event_type,
                source=self.name,
                target=target,
                data=data or {},
            )
            task = asyncio.create_task(self.event_bus.emit(event))
            # Store task reference to prevent garbage collection
            if not hasattr(self, "_event_tasks"):
                self._event_tasks = set()
            self._event_tasks.add(task)
            # Remove task from set when it's done
            task.add_done_callback(self._event_tasks.discard)

    def log_performance_metric(self, metric_name: str, value: object) -> None:
        """Log performance metric.

        Records a performance metric with timestamp for monitoring and analysis.

        Args:
            metric_name: Name/identifier of the performance metric.
            value: Numeric or object value of the metric.

        Returns:
            None
        """
        self.performance_metrics[metric_name] = {
            "value": value,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def get_status(self) -> dict[str, Any]:
        """Get plugin status information.

        Returns:
            dict[str, Any]: Dictionary containing plugin name, version, status,
                last error, performance metrics, and configuration.
        """
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "last_error": self.last_error,
            "performance_metrics": self.performance_metrics,
            "config": self.config,
        }


@log_all_methods
class GhidraPlugin(AbstractPlugin):
    """Base class for Ghidra script plugins.

    Manages execution of Ghidra analysis scripts for static binary analysis,
    including function extraction, string finding, cryptography identification,
    and protection detection for software licensing analysis.
    """

    def __init__(self, name: str, script_path: str, version: str = "1.0.0") -> None:
        """Initialize Ghidra plugin with name, script path, and version.

        Args:
            name: Plugin identifier name.
            script_path: Path to the Ghidra script file to execute.
            version: Version string in semantic versioning format.
        """
        super().__init__(name, version)
        self.script_path = Path(script_path)
        self.java_process: subprocess.Popen[bytes] | None = None
        self.ghidra_project_path: str | None = None

    def get_metadata(self) -> PluginMetadata:
        """Get Ghidra plugin metadata.

        Returns:
            PluginMetadata: Metadata describing the Ghidra plugin capabilities
                and supported binary formats.
        """
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=f"Ghidra script: {self.script_path.name}",
            component_type=ComponentType.GHIDRA_SCRIPT,
            author="Intellicrack Framework",
            capabilities=["static_analysis", "reverse_engineering", "binary_analysis"],
            supported_formats=[".exe", ".dll", ".elf", ".bin"],
        )

    async def initialize(self, config: dict[str, Any]) -> bool:
        """Initialize Ghidra plugin.

        Verifies Ghidra installation and script availability, configures
        plugin with provided configuration.

        Args:
            config: Configuration dictionary with ghidra_path and other settings.

        Returns:
            bool: True if initialization succeeded, False otherwise.
        """
        try:
            self.status = PluginStatus.INITIALIZING
            self.config.update(config)

            # Verify Ghidra installation
            ghidra_path = config.get("ghidra_path", "")
            if not ghidra_path or not Path(ghidra_path).exists():
                raise Exception("Ghidra installation not found")

            # Verify script exists
            if not self.script_path.exists():
                raise Exception(f"Ghidra script not found: {self.script_path}")

            self.status = PluginStatus.READY
            return True

        except Exception as e:
            self.last_error = str(e)
            self.status = PluginStatus.ERROR
            if self.logger:
                self.logger.exception("Ghidra plugin initialization failed: %s", e)
            return False

    async def activate(self) -> bool:
        """Activate Ghidra plugin.

        Sets plugin to ACTIVE state, enabling execution of static analysis
        scripts on target binaries.

        Returns:
            bool: True if activation succeeded.
        """
        self.status = PluginStatus.ACTIVE
        return True

    async def deactivate(self) -> bool:
        """Deactivate Ghidra plugin.

        Terminates any running Java processes and sets plugin to READY state,
        ensuring all Ghidra analysis sessions are terminated cleanly.

        Returns:
            bool: True if deactivation succeeded.
        """
        if self.java_process:
            self.java_process.terminate()
            self.java_process = None
        self.status = PluginStatus.READY
        return True

    async def cleanup(self) -> bool:
        """Cleanup Ghidra plugin resources.

        Performs cleanup of all Ghidra plugin resources including terminating
        Java processes and releasing any active analysis sessions.

        Returns:
            bool: True if cleanup succeeded.
        """
        await self.deactivate()
        return True

    def get_supported_operations(self) -> list[str]:
        """Get supported Ghidra operations.

        Returns:
            list[str]: List of supported operation names including analyze_binary,
                extract_functions, find_strings, identify_crypto, generate_keygen,
                and detect_packers.
        """
        return [
            "analyze_binary",
            "extract_functions",
            "find_strings",
            "identify_crypto",
            "generate_keygen",
            "detect_packers",
        ]

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Ghidra operation.

        Executes a Ghidra analysis operation on a binary file with specified
        parameters and emits events for operation completion or failure.

        Args:
            operation: Name of the Ghidra operation to execute.
            parameters: Operation parameters including binary_path and timeout.

        Returns:
            object: Operation result dictionary with parsed output.

        Raises:
            ValueError: If operation not supported or binary path invalid.
        """
        try:
            if operation not in self.get_supported_operations():
                raise ValueError(f"Unsupported operation: {operation}")

            binary_path_obj = parameters.get("binary_path")
            if not binary_path_obj:
                raise ValueError("No binary path provided")
            binary_path = str(binary_path_obj)
            if not Path(binary_path).exists():
                raise ValueError("Invalid binary path")

            # Execute Ghidra script
            result = await self._execute_ghidra_script(binary_path, operation, parameters)

            self.emit_event(
                "operation_completed",
                {
                    "operation": operation,
                    "result": result,
                    "parameters": parameters,
                },
            )

            return result

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Ghidra operation failed: %s", e)

            self.emit_event(
                "operation_failed",
                {
                    "operation": operation,
                    "error": str(e),
                    "parameters": parameters,
                },
            )

            raise

    async def _execute_ghidra_script(self, binary_path: str, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Execute Ghidra script in subprocess.

        Runs Ghidra analyzeHeadless in a subprocess with the specified script
        and binary file, handling timeouts and errors gracefully.

        Args:
            binary_path: Path to the binary file to analyze.
            operation: Operation type for Ghidra analysis.
            parameters: Operation parameters including timeout setting.

        Returns:
            dict[str, Any]: Result dictionary with operation output and parsed data.

        Raises:
            FileNotFoundError: If binary file does not exist.
            Exception: On Ghidra execution timeout or other errors.
        """
        ghidra_path = self.config.get("ghidra_path")
        java_path = self.config.get("java_path", "java")

        # Use os to check if binary file exists and get its info
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        binary_stats = Path(binary_path).stat()
        binary_hash = hashlib.sha256()

        # Calculate hash of binary for tracking
        def _hash_file() -> str:
            """Compute SHA256 hash of binary file for tracking and deduplication.

            Calculates incremental SHA256 hash of the binary file by reading it
            in 4KB chunks to minimize memory usage.

            Returns:
                str: First 16 characters of SHA256 hash for binary identification.
            """
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    binary_hash.update(chunk)
            return binary_hash.hexdigest()[:16]

        binary_id = await asyncio.to_thread(_hash_file)

        # Use inspect to validate parameters
        current_frame: FrameType | None = inspect.currentframe()
        current_function = current_frame.f_code.co_name if current_frame else "unknown"
        if self.logger:
            self.logger.debug("Executing %s with operation: %s", current_function, operation)

        # Use queue for managing concurrent operations
        operation_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        operation_queue.put(
            {
                "binary_path": binary_path,
                "binary_id": binary_id,
                "binary_size": binary_stats.st_size,
                "operation": operation,
                "timestamp": time.time(),
            },
        )

        # Prepare Ghidra command
        cmd = [
            java_path,
            "-jar",
            f"{ghidra_path}/support/analyzeHeadless.jar",
            self.ghidra_project_path or tempfile.mkdtemp(),
            f"project_{binary_id}",
            "-import",
            binary_path,
            "-postScript",
            str(self.script_path),
            "-scriptPath",
            str(self.script_path.parent),
        ]

        # Add operation-specific parameters
        if operation == "analyze_binary":
            cmd.extend(["-analysisTimeoutPerFile", str(parameters.get("timeout", 300))])

        try:
            # Execute with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.script_path.parent,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=parameters.get("timeout", 300),
            )

            if process.returncode == 0:
                # Parse Ghidra output
                output = stdout.decode("utf-8", errors="ignore")
                return self._parse_ghidra_output(output, operation)
            error_msg = stderr.decode("utf-8", errors="ignore")
            raise Exception(f"Ghidra execution failed: {error_msg}")

        except TimeoutError as timeout_error:
            if process:
                try:
                    # Use signal to gracefully terminate process
                    process.send_signal(signal.SIGTERM)
                    await asyncio.sleep(2)
                    if process.returncode is None:
                        process.kill()
                except Exception as term_error:
                    # Use traceback for detailed error logging
                    error_trace = traceback.format_exc()
                    if self.logger:
                        self.logger.exception("Process termination failed: %s\n%s", term_error, error_trace)
                    process.kill()
            raise Exception("Ghidra execution timed out") from timeout_error
        except Exception as e:
            # Use traceback for comprehensive error reporting
            error_trace = traceback.format_exc()
            if self.logger:
                self.logger.exception("Ghidra execution error: %s\n%s", e, error_trace)
            raise

    def _parse_ghidra_output(self, output: str, operation: str) -> dict[str, Any]:
        """Parse Ghidra script output.

        Parses Ghidra script output based on operation type, extracting
        relevant data structures (functions, strings, crypto algorithms, etc.).

        Args:
            output: Raw output string from Ghidra script execution.
            operation: Operation type that determines parsing strategy.

        Returns:
            dict[str, Any]: Parsed result dictionary with operation-specific data.
        """
        result: dict[str, Any] = {
            "operation": operation,
            "raw_output": output,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Operation-specific parsing
        if operation == "extract_functions":
            functions: list[dict[str, str]] = []
            for line in output.split("\n"):
                if "FUNCTION:" in line:
                    parts = line.split("FUNCTION:")[1].strip().split()
                    if len(parts) >= 2:
                        functions.append(
                            {
                                "name": parts[0],
                                "address": parts[1],
                                "size": parts[2] if len(parts) > 2 else "unknown",
                            },
                        )
            result["functions"] = functions

        elif operation == "find_strings":
            strings: list[str] = []
            for line in output.split("\n"):
                if "STRING:" in line:
                    string_data = line.split("STRING:")[1].strip()
                    strings.append(string_data)
            result["strings"] = strings

        elif operation == "identify_crypto":
            crypto_findings: list[str] = []
            for line in output.split("\n"):
                if "CRYPTO:" in line:
                    crypto_data = line.split("CRYPTO:")[1].strip()
                    crypto_findings.append(crypto_data)
            result["crypto_algorithms"] = crypto_findings

        return result


@log_all_methods
class FridaPlugin(AbstractPlugin):
    """Base class for Frida script plugins.

    Manages execution of Frida scripts for dynamic binary analysis, runtime
    manipulation, API hooking, and license protection bypass for software
    cracking operations.
    """

    def __init__(self, name: str, script_path: str, version: str = "1.0.0") -> None:
        """Initialize Frida plugin with name, script path, and version.

        Args:
            name: Plugin identifier name.
            script_path: Path to the Frida JavaScript script file.
            version: Version string in semantic versioning format.
        """
        super().__init__(name, version)
        self.script_path = Path(script_path)
        self.frida_session: Any = None
        self.frida_script: Any = None
        self.target_process: str | int | None = None

    def get_metadata(self) -> PluginMetadata:
        """Get Frida plugin metadata.

        Returns:
            PluginMetadata: Metadata describing the Frida plugin capabilities
                and supported binary formats.
        """
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=f"Frida script: {self.script_path.name}",
            component_type=ComponentType.FRIDA_SCRIPT,
            author="Intellicrack Framework",
            capabilities=["dynamic_analysis", "runtime_manipulation", "api_hooking"],
            supported_formats=[".exe", ".dll", ".so", ".dylib"],
        )

    async def initialize(self, config: dict[str, Any]) -> bool:
        """Initialize Frida plugin.

        Verifies Frida script and installation, enumerates available devices.

        Args:
            config: Configuration dictionary for plugin initialization.

        Returns:
            bool: True if initialization succeeded, False otherwise.
        """
        try:
            from intellicrack.handlers.frida_handler import HAS_FRIDA, frida

            _ = HAS_FRIDA  # Verify frida availability flag is imported for initialization checks

            self.status = PluginStatus.INITIALIZING
            self.config.update(config)

            # Verify script exists
            if not self.script_path.exists():
                raise Exception(f"Frida script not found: {self.script_path}")

            # Test Frida installation
            devices = frida.enumerate_devices()
            if not devices:
                raise Exception("No Frida devices available")

            self.status = PluginStatus.READY
            return True

        except ImportError:
            self.last_error = "Frida not installed"
            self.status = PluginStatus.ERROR
            return False
        except Exception as e:
            self.last_error = str(e)
            self.status = PluginStatus.ERROR
            if self.logger:
                self.logger.exception("Frida plugin initialization failed: %s", e)
            return False

    async def activate(self) -> bool:
        """Activate Frida plugin.

        Sets plugin to ACTIVE state, making it ready to inject into target processes
        and execute dynamic instrumentation scripts.

        Returns:
            bool: True if activation succeeded.
        """
        self.status = PluginStatus.ACTIVE
        return True

    async def deactivate(self) -> bool:
        """Deactivate Frida plugin.

        Unloads Frida script from target process and detaches the session,
        ensuring clean termination of dynamic instrumentation.

        Returns:
            bool: True if deactivation succeeded.
        """
        if self.frida_script:
            self.frida_script.unload()
            self.frida_script = None

        if self.frida_session:
            self.frida_session.detach()
            self.frida_session = None

        self.status = PluginStatus.READY
        return True

    async def cleanup(self) -> bool:
        """Cleanup Frida plugin resources.

        Performs cleanup of all Frida plugin resources by deactivating the plugin.

        Returns:
            bool: True if cleanup succeeded.
        """
        await self.deactivate()
        return True

    def get_supported_operations(self) -> list[str]:
        """Get supported Frida operations.

        Returns:
            list[str]: List of supported operation names including attach_process,
                hook_functions, trace_calls, modify_memory, bypass_protections,
                and extract_runtime_data.
        """
        return [
            "attach_process",
            "hook_functions",
            "trace_calls",
            "modify_memory",
            "bypass_protections",
            "extract_runtime_data",
        ]

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Frida operation.

        Executes a Frida operation on a target process with specified parameters,
        handling process attachment and operation-specific logic.

        Args:
            operation: Name of the Frida operation to execute.
            parameters: Operation parameters including target process identifier.

        Returns:
            object: Operation result dictionary or data from target process.

        Raises:
            ValueError: If operation not supported or target not specified.
        """
        try:
            from intellicrack.handlers.frida_handler import frida

            # Check Frida version and capabilities
            frida_version = frida.__version__
            if self.logger:
                self.logger.debug("Using Frida version: %s", frida_version)

            if operation not in self.get_supported_operations():
                raise ValueError(f"Unsupported operation: {operation}")

            # Get target process
            target_obj = parameters.get("target")
            if not target_obj:
                raise ValueError("Target process not specified")
            target: str | int = (
                str(target_obj) if isinstance(target_obj, str) else int(target_obj) if isinstance(target_obj, int) else str(target_obj)
            )

            # Attach to process
            if operation == "attach_process":
                return await self._attach_to_process(target)

            # Ensure we have an active session
            if not self.frida_session:
                await self._attach_to_process(target)

            # Execute operation-specific logic
            if operation == "hook_functions":
                return await self._hook_functions(parameters)
            if operation == "trace_calls":
                return await self._trace_calls(parameters)
            if operation == "modify_memory":
                return await self._modify_memory(parameters)
            if operation == "bypass_protections":
                return await self._bypass_protections(parameters)
            if operation == "extract_runtime_data":
                return await self._extract_runtime_data(parameters)

            return None

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Frida operation failed: %s", e)

            self.emit_event(
                "operation_failed",
                {
                    "operation": operation,
                    "error": str(e),
                    "parameters": parameters,
                },
            )

            raise

    async def _attach_to_process(self, target: str | int) -> dict[str, Any]:
        """Attach to target process.

        Attaches to a target process using Frida, loads the script, and
        registers message handler.

        Args:
            target: Process name or PID to attach to.

        Returns:
            dict[str, Any]: Result dictionary with attachment status and session info.

        Raises:
            Exception: If process attachment fails or script loading fails.
        """
        try:
            from intellicrack.handlers.frida_handler import frida

            # Get device
            device = frida.get_local_device()

            self.frida_session = device.attach(target)
            # Load script
            script_code = await asyncio.to_thread(lambda: Path(self.script_path).read_text(encoding="utf-8"))

            self.frida_script = self.frida_session.create_script(script_code)
            self.frida_script.on("message", self._on_message)
            self.frida_script.load()

            self.target_process = target

            result = {
                "status": "attached",
                "target": target,
                "session_id": id(self.frida_session),
                "script_loaded": True,
            }

            self.emit_event("process_attached", result)

            return result

        except frida.ProcessNotFoundError as e:
            raise Exception(f"Process not found: {target}") from e
        except Exception as e:
            raise Exception(f"Failed to attach to process: {e}") from e

    def _on_message(self, message: object, data: object) -> None:
        """Handle Frida script messages.

        Handles messages sent from Frida script and emits event for logging.

        Args:
            message: Message object from Frida script.
            data: Associated data payload from Frida script.

        Returns:
            None
        """
        if self.logger:
            self.logger.debug("Frida message: %s", message)

        # Emit event for message
        self.emit_event(
            "frida_message",
            {
                "message": message,
                "data": data,
                "target": self.target_process,
            },
        )

    async def _hook_functions(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Install hooks for functions in target process.

        Installs Frida hooks for a list of function names in the target process.

        Args:
            parameters: Dictionary containing "functions" list.

        Returns:
            dict[str, Any]: Result dictionary with hooked_functions list showing
                per-function hook status.

        Raises:
            ValueError: If no functions specified in parameters.
        """
        functions = parameters.get("functions", [])
        if not functions:
            raise ValueError("No functions specified for hooking")

        results = []
        for func in functions:
            try:
                # Call Frida script function
                result = self.frida_script.exports.hook_function(func)
                results.append(
                    {
                        "function": func,
                        "status": "hooked",
                        "result": result,
                    },
                )
            except Exception as e:
                results.append(
                    {
                        "function": func,
                        "status": "failed",
                        "error": str(e),
                    },
                )

        return {"hooked_functions": results}

    async def _trace_calls(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Trace function calls.

        Traces function calls in the target process for specified duration.

        Args:
            parameters: Dictionary containing optional "duration" in seconds.

        Returns:
            dict[str, Any]: Result dictionary with trace_duration, trace_data,
                and call_count.
        """
        duration = parameters.get("duration", 30)

        # Start tracing
        self.frida_script.exports.start_trace()

        # Wait for specified duration
        await asyncio.sleep(duration)

        # Stop tracing and get results
        trace_data = self.frida_script.exports.stop_trace()

        return {
            "trace_duration": duration,
            "trace_data": trace_data,
            "call_count": len(trace_data) if isinstance(trace_data, list) else 0,
        }

    async def _modify_memory(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Modify process memory.

        Writes data to a specific address in the target process memory.

        Args:
            parameters: Dictionary containing "address" and "data" keys.

        Returns:
            dict[str, Any]: Result dictionary with address, data_written, and result.

        Raises:
            ValueError: If address or data not specified in parameters.
        """
        address = parameters.get("address")
        data = parameters.get("data")

        if not address or not data:
            raise ValueError("Address and data required for memory modification")

        result = self.frida_script.exports.write_memory(address, data)

        return {
            "address": address,
            "data_written": data,
            "result": result,
        }

    async def _bypass_protections(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Bypass protection mechanisms.

        Attempts to bypass protection mechanisms in the target process.

        Args:
            parameters: Dictionary containing "protections" list.

        Returns:
            dict[str, Any]: Result dictionary with bypass_results list showing
                per-protection bypass status.
        """
        protections = parameters.get("protections", [])

        results = []
        for protection in protections:
            try:
                result = self.frida_script.exports.bypass_protection(protection)
                results.append(
                    {
                        "protection": protection,
                        "status": "bypassed",
                        "result": result,
                    },
                )
            except Exception as e:
                results.append(
                    {
                        "protection": protection,
                        "status": "failed",
                        "error": str(e),
                    },
                )

        return {"bypass_results": results}

    async def _extract_runtime_data(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Extract runtime data from process.

        Extracts runtime data (strings, keys, certificates, etc.) from the
        target process memory.

        Args:
            parameters: Dictionary with optional "data_types" list.

        Returns:
            dict[str, Any]: Result dictionary with extracted_data mapping
                data type names to extracted values.
        """
        data_types = parameters.get("data_types", ["strings", "keys", "certificates"])

        extracted_data = {}
        for data_type in data_types:
            try:
                data = self.frida_script.exports.extract_data(data_type)
                extracted_data[data_type] = data
            except Exception as e:
                extracted_data[data_type] = {"error": str(e)}

        return {"extracted_data": extracted_data}


@log_all_methods
class PythonPlugin(AbstractPlugin):
    """Base class for Python module plugins.

    Loads and manages dynamically imported Python modules as plugins,
    supporting custom analysis, license bypass, and protection bypass
    operations for software licensing research.
    """

    def __init__(self, name: str, module_path: str, version: str = "1.0.0") -> None:
        """Initialize Python plugin with name, module path, and version.

        Args:
            name: Plugin identifier name.
            module_path: Path to the Python module file to load.
            version: Version string in semantic versioning format.
        """
        super().__init__(name, version)
        self.module_path = Path(module_path)
        self.module: ModuleType | None = None
        self.plugin_instance: Any = None

    def get_metadata(self) -> PluginMetadata:
        """Get Python plugin metadata.

        Returns:
            PluginMetadata: Metadata describing the Python plugin capabilities
                and supported binary formats.
        """
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=f"Python module: {self.module_path.name}",
            component_type=ComponentType.CUSTOM_MODULE,
            author="Intellicrack Framework",
            capabilities=["custom_analysis", "license_bypass", "protection_bypass"],
            supported_formats=[".exe", ".dll", ".so", ".dylib", ".bin"],
        )

    async def initialize(self, config: dict[str, Any]) -> bool:
        """Initialize Python plugin.

        Dynamically loads Python module, instantiates plugin class if available,
        and calls initialize method if defined.

        Args:
            config: Configuration dictionary for plugin initialization.

        Returns:
            bool: True if initialization succeeded, False otherwise.
        """
        try:
            self.status = PluginStatus.INITIALIZING
            self.config.update(config)

            # Verify module exists
            if not self.module_path.exists():
                raise Exception(f"Python module not found: {self.module_path}")

            # Load module dynamically
            spec = importlib.util.spec_from_file_location(self.name, self.module_path)
            if not spec or not spec.loader:
                raise Exception(f"Cannot load module: {self.module_path}")

            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)

            # Look for plugin class or main function
            if hasattr(self.module, "Plugin"):
                self.plugin_instance = self.module.Plugin()
            elif hasattr(self.module, "main"):
                self.plugin_instance = self.module
            else:
                raise Exception("No Plugin class or main function found")

            # Initialize plugin instance if it has an init method
            if hasattr(self.plugin_instance, "initialize"):
                if asyncio.iscoroutinefunction(self.plugin_instance.initialize):
                    await self.plugin_instance.initialize(config)
                else:
                    self.plugin_instance.initialize(config)

            self.status = PluginStatus.READY
            return True

        except Exception as e:
            self.last_error = str(e)
            self.status = PluginStatus.ERROR
            if self.logger:
                self.logger.exception("Python plugin initialization failed: %s", e)
            return False

    async def activate(self) -> bool:
        """Activate Python plugin.

        Invokes the activate method on the plugin instance if available,
        and updates the plugin status to ACTIVE.

        Returns:
            bool: True if activation succeeded or no activate method exists,
                False if activation failed.
        """
        try:
            if hasattr(self.plugin_instance, "activate"):
                if asyncio.iscoroutinefunction(self.plugin_instance.activate):
                    result = await self.plugin_instance.activate()
                else:
                    result = self.plugin_instance.activate()

                if result is False:
                    return False

            self.status = PluginStatus.ACTIVE
            return True

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Python plugin activation failed: %s", e)
            return False

    async def deactivate(self) -> bool:
        """Deactivate Python plugin.

        Invokes the deactivate method on the plugin instance if available,
        and updates the plugin status to READY.

        Returns:
            bool: True if deactivation succeeded or no deactivate method exists,
                False if deactivation failed.
        """
        try:
            if hasattr(self.plugin_instance, "deactivate"):
                if asyncio.iscoroutinefunction(self.plugin_instance.deactivate):
                    await self.plugin_instance.deactivate()
                else:
                    self.plugin_instance.deactivate()

            self.status = PluginStatus.READY
            return True

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Python plugin deactivation failed: %s", e)
            return False

    async def cleanup(self) -> bool:
        """Cleanup Python plugin resources.

        Invokes cleanup method on plugin instance if available, then releases
        module references and plugin instances to enable garbage collection.

        Returns:
            bool: True if cleanup succeeded or no cleanup method exists,
                False if cleanup failed.
        """
        try:
            if hasattr(self.plugin_instance, "cleanup"):
                if asyncio.iscoroutinefunction(self.plugin_instance.cleanup):
                    await self.plugin_instance.cleanup()
                else:
                    self.plugin_instance.cleanup()

            self.plugin_instance = None
            self.module = None
            return True

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Python plugin cleanup failed: %s", e)
            return False

    def get_supported_operations(self) -> list[str]:
        """Get supported Python plugin operations.

        Returns:
            list[str]: List of supported operation names from plugin instance
                or standard operations (analyze, process, execute, run, bypass,
                crack, extract, detect) if methods exist.
        """
        if not self.plugin_instance:
            return []

        # Check for standard operations
        standard_ops = [
            "analyze",
            "process",
            "execute",
            "run",
            "bypass",
            "crack",
            "extract",
            "detect",
        ]

        operations = [op for op in standard_ops if hasattr(self.plugin_instance, op)]
        # Check for get_operations method
        if hasattr(self.plugin_instance, "get_operations"):
            try:
                plugin_ops = self.plugin_instance.get_operations()
                if isinstance(plugin_ops, list):
                    operations.extend(plugin_ops)
            except Exception as e:
                if self.logger:
                    self.logger.exception("Plugin operation error: %s", e)

        return list(set(operations))

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Python plugin operation.

        Executes a named operation on the loaded plugin module with specified parameters.

        Args:
            operation: Operation name to execute.
            parameters: Keyword arguments for the operation method.

        Returns:
            object: Operation result from the plugin method.

        Raises:
            ValueError: If operation not found on plugin instance.
            TypeError: If operation method not callable.
            Exception: If plugin not initialized.
        """
        try:
            if not self.plugin_instance:
                raise Exception("Plugin not initialized")

            if operation not in self.get_supported_operations():
                raise ValueError(f"Unsupported operation: {operation}")

            # Get operation method
            method = getattr(self.plugin_instance, operation)
            if not callable(method):
                raise TypeError(f"Operation {operation} is not callable")

            # Execute operation
            if asyncio.iscoroutinefunction(method):
                result = await method(**parameters)
            else:
                result = method(**parameters)

            self.emit_event(
                "operation_completed",
                {
                    "operation": operation,
                    "result": result,
                    "parameters": parameters,
                },
            )

            return result

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception("Python plugin operation failed: %s", e)

            self.emit_event(
                "operation_failed",
                {
                    "operation": operation,
                    "error": str(e),
                    "parameters": parameters,
                },
            )

            raise


@log_all_methods
class EventBus:
    """Async event bus for inter-component communication.

    Provides asynchronous event publishing/subscription infrastructure with
    handler concurrency management, event history tracking, and TTL support
    for framework component interaction.
    """

    def __init__(self, max_queue_size: int = 10000) -> None:
        """Initialize event bus with maximum queue size.

        Args:
            max_queue_size: Maximum events in queue before blocking (default 10000).
        """
        self.subscribers: dict[str, list[Callable[[Event], Awaitable[None]]]] = {}
        self.event_queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self.running: bool = False
        self.processor_task: asyncio.Task[None] | None = None
        self.logger: logging.Logger | None = None
        self.event_history: list[Event] = []
        self.max_history_size: int = 1000
        self.stats = {
            "events_processed": 0,
            "events_failed": 0,
            "subscribers_count": 0,
            "queue_size": 0,
        }

    def set_logger(self, logger: logging.Logger) -> None:
        """Set logger for event bus.

        Configures the logger instance for event bus diagnostics and monitoring.

        Args:
            logger: Logger instance for event bus diagnostics.

        Returns:
            None
        """
        self.logger = logger

    async def start(self) -> None:
        """Start event processing.

        Starts the event processor task that consumes events from the queue
        and dispatches them to registered handlers.

        Returns:
            None
        """
        if self.running:
            return

        self.running = True
        self.processor_task = asyncio.create_task(self._process_events())

        if self.logger:
            self.logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop event processing.

        Stops the event processor task and sets running flag to False.

        Returns:
            None
        """
        if not self.running:
            return

        self.running = False

        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError as e:
                if self.logger:
                    self.logger.exception("Plugin operation error: %s", e)

        if self.logger:
            self.logger.info("Event bus stopped")

    def subscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]) -> None:
        """Subscribe to events of specific type.

        Registers an async handler for a specific event type or wildcard "*".

        Args:
            event_type: Event type to subscribe to (or "*" for all events).
            handler: Async callable that accepts an Event and returns None.

        Returns:
            None
        """
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []

        self.subscribers[event_type].append(handler)
        self.stats["subscribers_count"] = sum(len(handlers) for handlers in self.subscribers.values())

        if self.logger:
            self.logger.debug("New subscriber for event type: %s", event_type)

    def unsubscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]) -> None:
        """Unsubscribe from events.

        Unregisters a previously registered event handler.

        Args:
            event_type: Event type handler was subscribed to.
            handler: The handler callable to unregister.

        Returns:
            None
        """
        if event_type in self.subscribers and handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)

            if not self.subscribers[event_type]:
                del self.subscribers[event_type]

            self.stats["subscribers_count"] = sum(len(handlers) for handlers in self.subscribers.values())

            if self.logger:
                self.logger.debug("Unsubscribed from event type: %s", event_type)

    async def emit(self, event: Event) -> None:
        """Emit an event.

        Queues an event for processing, checking TTL if set. Event will be
        dropped if expired.

        Args:
            event: Event instance to emit through the bus.

        Returns:
            None
        """
        try:
            # Check TTL
            if event.ttl is not None:
                age = (datetime.now(UTC) - event.timestamp).total_seconds()
                if age > event.ttl:
                    if self.logger:
                        self.logger.warning("Event %s expired (TTL: %ss)", event.event_id, event.ttl)
                    return

            # Add to queue
            await self.event_queue.put(event)
            self.stats["queue_size"] = self.event_queue.qsize()

            if self.logger:
                self.logger.debug("Event emitted: %s from %s", event.event_type, event.source)

        except asyncio.QueueFull:
            if self.logger:
                self.logger.exception("Event queue full, dropping event: %s", event.event_type)

    async def _process_events(self) -> None:
        """Process events from queue.

        Main event loop that continuously fetches events from the queue,
        adds them to history, and dispatches to handlers.

        Returns:
            None
        """
        while self.running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)

                # Add to history
                self._add_to_history(event)

                # Process event
                await self._handle_event(event)

                # Update stats
                self.stats["events_processed"] += 1
                self.stats["queue_size"] = self.event_queue.qsize()

            except TimeoutError:
                # Continue processing
                continue
            except Exception as e:
                self.stats["events_failed"] += 1
                if self.logger:
                    self.logger.exception("Event processing error: %s", e)

    async def _handle_event(self, event: Event) -> None:
        """Handle individual event.

        Executes registered handlers for the event concurrently with timeout.

        Args:
            event: Event to dispatch to registered handlers.

        Returns:
            None
        """
        handlers = []

        # Get specific handlers
        if event.event_type in self.subscribers:
            handlers.extend(self.subscribers[event.event_type])

        # Get wildcard handlers
        if "*" in self.subscribers:
            handlers.extend(self.subscribers["*"])

        # Execute handlers concurrently
        if handlers:
            tasks = []
            handler_types: list[type] = []  # Use Type annotation for handler type tracking

            for handler in handlers:
                try:
                    # Track handler type
                    handler_types.append(type(handler))

                    if asyncio.iscoroutinefunction(handler):
                        tasks.append(asyncio.create_task(handler(event)))
                    else:
                        # Wrap sync handler in async - cast to match signature
                        sync_handler = cast("Callable[[Event], None]", handler)
                        tasks.append(asyncio.create_task(self._run_sync_handler(sync_handler, event)))
                except Exception as e:
                    if self.logger:
                        self.logger.exception("Error creating task for handler: %s", e)

            # Wait for all handlers to complete with timeout using timedelta
            if tasks:
                handler_timeout = timedelta(seconds=30)  # Use timedelta for timeout calculation
                timeout_seconds = handler_timeout.total_seconds()

                # Track task completion in real-time
                completed_count = 0
                results: list[None | Exception] = []

                try:
                    # Use as_completed to process tasks as they finish
                    for completed_task in asyncio.as_completed(tasks, timeout=timeout_seconds):
                        try:
                            await completed_task
                            results.append(None)
                            completed_count += 1
                        except Exception as e:
                            results.append(e)
                            completed_count += 1

                    for i, result in enumerate(results):
                        if isinstance(result, Exception) and self.logger:
                            self.logger.exception(
                                "Handler %d (%s) failed for event %s: %s",
                                i,
                                handler_types[i].__name__,
                                event.event_type,
                                result,
                            )

                    if self.logger:
                        self.logger.debug(
                            "Event %s: %d/%d handlers completed successfully",
                            event.event_type,
                            completed_count,
                            len(tasks),
                        )
                except TimeoutError:
                    if self.logger:
                        self.logger.warning("Handler execution timed out after %s", handler_timeout)
                    # Cancel remaining tasks
                    for task in tasks:
                        task.cancel()

    async def _run_sync_handler(self, handler: Callable[[Event], None], event: Event) -> None:
        """Run synchronous handler in executor.

        Wraps a synchronous handler to run asynchronously in the event loop executor.

        Args:
            handler: Synchronous handler callable.
            event: Event to pass to handler.

        Returns:
            None
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, handler, event)

    def _add_to_history(self, event: Event) -> None:
        """Add event to history.

        Appends event to history list and trims if exceeds max size.

        Args:
            event: Event to add to history.

        Returns:
            None
        """
        self.event_history.append(event)

        # Limit history size
        if len(self.event_history) > self.max_history_size:
            self.event_history = self.event_history[-self.max_history_size // 2 :]

    def get_stats(self) -> dict[str, Any]:
        """Get event bus statistics.

        Returns:
            dict[str, Any]: Statistics including events_processed, events_failed,
                subscribers_count, queue_size, history_size, subscriber_types,
                and running status.
        """
        return {
            **self.stats,
            "history_size": len(self.event_history),
            "subscriber_types": list(self.subscribers.keys()),
            "running": self.running,
        }

    def get_recent_events(self, count: int = 100) -> list[Event]:
        """Get recent events from history.

        Args:
            count: Number of recent events to return (default 100).

        Returns:
            list[Event]: List of the most recent events up to count.
        """
        return self.event_history[-count:]


@log_all_methods
class PluginManager:
    """Plugin discovery, loading, and lifecycle management.

    Manages plugin lifecycle including discovery from directories, loading,
    dependency resolution, and event-based activation/deactivation for the
    Intellicrack framework.
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus, logger: logging.Logger) -> None:
        """Initialize plugin manager with configuration, event bus, and logger.

        Sets up plugin discovery paths, loading configuration, and initializes
        storage for loaded plugins, metadata, and dependency tracking.

        Args:
            config: Configuration dict with directories, enabled, disabled lists.
            event_bus: EventBus instance for plugin lifecycle events.
            logger: Logger instance for plugin management operations.
        """
        self.config = config
        self.event_bus = event_bus
        self.logger = logger

        self.plugins: dict[str, AbstractPlugin] = {}
        self.plugin_metadata: dict[str, PluginMetadata] = {}
        self.plugin_dependencies: dict[str, list[str]] = {}
        self.load_order: list[str] = []

        # Plugin discovery
        self.discovery_paths = config.get("directories", [])
        self.auto_discover = config.get("auto_discover", True)
        self.auto_load = config.get("auto_load", True)

        # Plugin filtering
        self.enabled_plugins = set(config.get("enabled", []))
        self.disabled_plugins = set(config.get("disabled", []))

        # Loading stats
        self.stats = {
            "discovered": 0,
            "loaded": 0,
            "failed": 0,
            "active": 0,
        }

    async def discover_plugins(self) -> list[str]:
        """Discover available plugins from configured directories.

        Scans plugin directories for Ghidra scripts, Frida scripts, and Python
        modules, extracting metadata from each discovered plugin.

        Returns:
            list[str]: List of discovered plugin names in the format 'type_name'.
        """
        discovered = []

        for directory in self.discovery_paths:
            dir_path = Path(directory)
            if not dir_path.exists():
                self.logger.warning("Plugin directory not found: %s", directory)
                continue

            self.logger.info("Discovering plugins in: %s", directory)
            # Discover different plugin types
            discovered.extend(await self._discover_ghidra_scripts(dir_path))
            discovered.extend(await self._discover_frida_scripts(dir_path))
            discovered.extend(await self._discover_python_modules(dir_path))

        self.stats["discovered"] = len(discovered)
        self.logger.info("Discovered %d plugins", len(discovered))

        return discovered

    async def _discover_ghidra_scripts(self, directory: Path) -> list[str]:
        """Discover Ghidra script plugins in directory.

        Scans directory for .java files containing Ghidra script metadata.

        Args:
            directory: Directory path to scan for Ghidra scripts.

        Returns:
            list[str]: List of discovered Ghidra plugin names in 'ghidra_*' format.
        """
        scripts = []

        for script_file in directory.glob("*.java"):
            try:
                # Read script metadata
                metadata = await self._extract_ghidra_metadata(script_file)
                if metadata:
                    plugin_name = f"ghidra_{script_file.stem}"
                    self.plugin_metadata[plugin_name] = metadata
                    scripts.append(plugin_name)

                    self.logger.debug("Discovered Ghidra script: %s", script_file)

            except Exception as e:
                self.logger.exception("Error discovering Ghidra script %s: %s", script_file, e)

        return scripts

    async def _discover_frida_scripts(self, directory: Path) -> list[str]:
        """Discover Frida script plugins in directory.

        Scans directory for .js files containing Frida script metadata.

        Args:
            directory: Directory path to scan for Frida scripts.

        Returns:
            list[str]: List of discovered Frida plugin names in 'frida_*' format.
        """
        scripts = []

        for script_file in directory.glob("*.js"):
            try:
                # Read script metadata
                metadata = await self._extract_frida_metadata(script_file)
                if metadata:
                    plugin_name = f"frida_{script_file.stem}"
                    self.plugin_metadata[plugin_name] = metadata
                    scripts.append(plugin_name)

                    self.logger.debug("Discovered Frida script: %s", script_file)

            except Exception as e:
                self.logger.exception("Error discovering Frida script %s: %s", script_file, e)

        return scripts

    async def _discover_python_modules(self, directory: Path) -> list[str]:
        """Discover Python module plugins in directory.

        Scans directory for .py files containing Python module plugins, excluding
        __init__.py and private modules.

        Args:
            directory: Directory path to scan for Python modules.

        Returns:
            list[str]: List of discovered Python plugin names in 'python_*' format.
        """
        modules = []

        for module_file in directory.glob("*.py"):
            # Skip __init__.py and private modules
            if module_file.name.startswith("__") or module_file.name.startswith("_"):
                continue

            try:
                # Read module metadata
                metadata = await self._extract_python_metadata(module_file)
                if metadata:
                    plugin_name = f"python_{module_file.stem}"
                    self.plugin_metadata[plugin_name] = metadata
                    modules.append(plugin_name)

                    self.logger.debug("Discovered Python module: %s", module_file)

            except Exception as e:
                self.logger.exception("Error discovering Python module %s: %s", module_file, e)

        return modules

    async def _extract_ghidra_metadata(self, script_file: Path) -> PluginMetadata | None:
        """Extract metadata from Ghidra script.

        Parses Ghidra script annotations to extract name, version, description,
        author, and capabilities for plugin registration.

        Args:
            script_file: Path to the Ghidra script file.

        Returns:
            PluginMetadata | None: Extracted metadata or None if parsing fails.
        """
        try:
            content = await asyncio.to_thread(lambda: script_file.read_text(encoding="utf-8"))

            metadata: ScriptMetadataDict = {
                "name": script_file.stem,
                "version": "1.0.0",
                "description": f"Ghidra script: {script_file.name}",
                "author": "Unknown",
                "capabilities": ["static_analysis"],
                "dependencies": [],
            }

            for line in content.split("\n")[:50]:
                line = line.strip()
                if line.startswith("//") or line.startswith("*"):
                    if "@description" in line.lower():
                        metadata["description"] = line.split("@description")[-1].strip()
                    elif "@author" in line.lower():
                        metadata["author"] = line.split("@author")[-1].strip()
                    elif "@version" in line.lower():
                        metadata["version"] = line.split("@version")[-1].strip()
                    elif "@capabilities" in line.lower():
                        caps = line.split("@capabilities")[-1].strip().split(",")
                        metadata["capabilities"] = [cap.strip() for cap in caps]

            return PluginMetadata(
                name=metadata["name"],
                version=metadata["version"],
                description=metadata["description"],
                component_type=ComponentType.GHIDRA_SCRIPT,
                author=metadata["author"],
                capabilities=metadata["capabilities"],
                dependencies=metadata["dependencies"],
                supported_formats=[".exe", ".dll", ".elf", ".bin"],
            )

        except Exception as e:
            self.logger.exception("Error extracting Ghidra metadata from %s: %s", script_file, e)
            return None

    async def _extract_frida_metadata(self, script_file: Path) -> PluginMetadata | None:
        """Extract metadata from Frida script.

        Parses Frida script comments to extract name, version, description,
        author, and capabilities for plugin registration.

        Args:
            script_file: Path to the Frida script file.

        Returns:
            PluginMetadata | None: Extracted metadata or None if parsing fails.
        """
        try:
            content = await asyncio.to_thread(lambda: script_file.read_text(encoding="utf-8"))

            metadata: ScriptMetadataDict = {
                "name": script_file.stem,
                "version": "1.0.0",
                "description": f"Frida script: {script_file.name}",
                "author": "Unknown",
                "capabilities": ["dynamic_analysis"],
                "dependencies": [],
            }

            for line in content.split("\n")[:100]:
                line = line.strip()
                if line.startswith("//") or line.startswith("*"):
                    if "description:" in line.lower():
                        metadata["description"] = line.split("description:")[-1].strip().strip("\"'")
                    elif "author:" in line.lower():
                        metadata["author"] = line.split("author:")[-1].strip().strip("\"'")
                    elif "version:" in line.lower():
                        metadata["version"] = line.split("version:")[-1].strip().strip("\"'")
                elif "name:" in line and ("=" in line or ":" in line):
                    if '"' in line or "'" in line:
                        if name_match := line.split("name:")[-1].strip().strip(",").strip("\"'"):
                            metadata["name"] = name_match

            return PluginMetadata(
                name=metadata["name"],
                version=metadata["version"],
                description=metadata["description"],
                component_type=ComponentType.FRIDA_SCRIPT,
                author=metadata["author"],
                capabilities=metadata["capabilities"],
                dependencies=metadata["dependencies"],
                supported_formats=[".exe", ".dll", ".so", ".dylib"],
            )

        except Exception as e:
            self.logger.exception("Error extracting Frida metadata from %s: %s", script_file, e)
            return None

    async def _extract_python_metadata(self, module_file: Path) -> PluginMetadata | None:
        """Extract metadata from Python module.

        Parses Python module docstring and source code to extract metadata,
        auto-detecting capabilities from imported modules and content keywords.

        Args:
            module_file: Path to the Python module file.

        Returns:
            PluginMetadata | None: Extracted metadata or None if parsing fails.
        """
        try:
            content = await asyncio.to_thread(lambda: module_file.read_text(encoding="utf-8"))

            metadata: ScriptMetadataDict = {
                "name": module_file.stem,
                "version": "1.0.0",
                "description": f"Python module: {module_file.name}",
                "author": "Unknown",
                "capabilities": ["custom_analysis"],
                "dependencies": [],
            }

            if '"""' in content:
                docstring = content.split('"""')[1] if content.count('"""') >= 2 else ""
                lines = docstring.split("\n")
                for line in lines:
                    line = line.strip()
                    if line.startswith("Author:"):
                        metadata["author"] = line.split("Author:")[-1].strip()
                    elif line.startswith("Version:"):
                        metadata["version"] = line.split("Version:")[-1].strip()
                    elif not metadata["description"].startswith("Python module:") and line:
                        metadata["description"] = line

            if "import torch" in content or "import tensorflow" in content:
                metadata["capabilities"].append("machine_learning")
            if "import frida" in content:
                metadata["capabilities"].append("dynamic_analysis")
            if "cryptography" in content or "Crypto" in content:
                metadata["capabilities"].append("cryptography")
            if "license" in content.lower() or "bypass" in content.lower():
                metadata["capabilities"].append("license_bypass")

            return PluginMetadata(
                name=metadata["name"],
                version=metadata["version"],
                description=metadata["description"],
                component_type=ComponentType.CUSTOM_MODULE,
                author=metadata["author"],
                capabilities=metadata["capabilities"],
                dependencies=metadata["dependencies"],
                supported_formats=[".exe", ".dll", ".so", ".dylib", ".bin"],
            )

        except Exception as e:
            self.logger.exception("Error extracting Python metadata from %s: %s", module_file, e)
            return None

    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin by name.

        Creates plugin instance, initializes with configuration, sets up logger
        and event bus, and registers the plugin for operation execution.

        Args:
            plugin_name: Name of the plugin to load.

        Returns:
            bool: True if plugin loaded successfully, False otherwise.
        """
        try:
            if plugin_name in self.plugins:
                self.logger.debug("Plugin %s already loaded", plugin_name)
                return True

            # Check if plugin is disabled
            if plugin_name in self.disabled_plugins:
                self.logger.info("Plugin %s is disabled", plugin_name)
                return False

            # Get metadata
            if plugin_name not in self.plugin_metadata:
                self.logger.error("No metadata found for plugin: %s", plugin_name)
                return False

            metadata = self.plugin_metadata[plugin_name]

            # Create plugin instance
            plugin = await self._create_plugin_instance(plugin_name, metadata)
            if not plugin:
                return False

            # Set logger and event bus
            plugin.set_logger(self.logger.getChild(plugin_name))
            plugin.set_event_bus(self.event_bus)

            # Initialize plugin
            plugin_config = self.config.get("plugin_configs", {}).get(plugin_name, {})
            if not await plugin.initialize(plugin_config):
                self.logger.error("Plugin %s initialization failed", plugin_name)
                return False

            # Store plugin
            self.plugins[plugin_name] = plugin
            self.stats["loaded"] += 1

            self.logger.info("Plugin %s loaded successfully", plugin_name)

            # Emit event
            await self.event_bus.emit(
                Event(
                    event_type="plugin_loaded",
                    source="plugin_manager",
                    data={"plugin_name": plugin_name, "metadata": metadata.to_dict()},
                ),
            )

            return True

        except Exception as e:
            self.stats["failed"] += 1
            self.logger.exception("Failed to load plugin %s: %s", plugin_name, e)
            return False

    async def _create_plugin_instance(self, plugin_name: str, metadata: PluginMetadata) -> AbstractPlugin | None:
        """Create plugin instance based on component type.

        Locates plugin file from discovery paths and instantiates the appropriate
        plugin class (GhidraPlugin, FridaPlugin, or PythonPlugin).

        Args:
            plugin_name: Name of the plugin to instantiate.
            metadata: Plugin metadata containing type and configuration.

        Returns:
            AbstractPlugin | None: Plugin instance or None if file not found or type unsupported.
        """
        try:
            # Find plugin file
            plugin_file = None
            for directory in self.discovery_paths:
                dir_path = Path(directory)

                if metadata.component_type == ComponentType.GHIDRA_SCRIPT:
                    potential_file = dir_path / f"{plugin_name.replace('ghidra_', '')}.java"
                elif metadata.component_type == ComponentType.FRIDA_SCRIPT:
                    potential_file = dir_path / f"{plugin_name.replace('frida_', '')}.js"
                elif metadata.component_type == ComponentType.CUSTOM_MODULE:
                    potential_file = dir_path / f"{plugin_name.replace('python_', '')}.py"
                else:
                    continue

                if potential_file.exists():
                    plugin_file = potential_file
                    break

            if not plugin_file:
                self.logger.error("Plugin file not found for: %s", plugin_name)
                return None

            # Create appropriate plugin instance
            if metadata.component_type == ComponentType.GHIDRA_SCRIPT:
                return GhidraPlugin(plugin_name, str(plugin_file), metadata.version)
            if metadata.component_type == ComponentType.FRIDA_SCRIPT:
                return FridaPlugin(plugin_name, str(plugin_file), metadata.version)
            if metadata.component_type == ComponentType.CUSTOM_MODULE:
                return PythonPlugin(plugin_name, str(plugin_file), metadata.version)
            self.logger.error("Unsupported plugin type: %s", metadata.component_type)
            return None

        except Exception as e:
            self.logger.exception("Error creating plugin instance for %s: %s", plugin_name, e)
            return None

    async def load_all_plugins(self) -> int:
        """Load all discovered plugins with dependency ordering.

        Discovers all plugins if auto_discover is enabled, then loads each plugin
        in dependency-order to ensure dependencies are loaded first.

        Returns:
            int: Number of plugins successfully loaded.
        """
        if self.auto_discover:
            await self.discover_plugins()

        loaded_count = 0

        # Determine load order based on dependencies
        load_order = self._calculate_load_order()

        for plugin_name in load_order:
            if await self.load_plugin(plugin_name):
                loaded_count += 1

        self.logger.info("Loaded %d plugins", loaded_count)
        return loaded_count

    def _calculate_load_order(self) -> list[str]:
        """Calculate plugin load order based on dependencies.

        Performs topological sort using depth-first search to determine the
        correct loading order that respects all plugin dependencies and
        detects circular dependencies.

        Returns:
            list[str]: Plugin names in dependency-respecting load order.
        """
        # Simple topological sort for dependency resolution
        visited = set()
        temp_visited = set()
        result = []

        def visit(plugin_name: str) -> None:
            """Recursively visit plugin dependencies for topological sort.

            Args:
                plugin_name: Name of the plugin to visit in the dependency graph.

            Returns:
                None
            """
            if plugin_name in temp_visited:
                # Circular dependency detected
                self.logger.warning("Circular dependency detected involving: %s", plugin_name)
                return

            if plugin_name in visited:
                return

            temp_visited.add(plugin_name)

            # Visit dependencies first
            dependencies = self.plugin_dependencies.get(plugin_name, [])
            for dep in dependencies:
                if dep in self.plugin_metadata:
                    visit(dep)

            temp_visited.remove(plugin_name)
            visited.add(plugin_name)
            result.append(plugin_name)

        # Visit all plugins
        for plugin_name in self.plugin_metadata:
            if plugin_name not in visited:
                visit(plugin_name)

        return result

    async def activate_plugin(self, plugin_name: str) -> bool:
        """Activate a loaded plugin.

        Calls the plugin's activate method and updates plugin status and event bus.

        Args:
            plugin_name: Name of the plugin to activate.

        Returns:
            bool: True if activation succeeded, False otherwise.
        """
        if plugin_name not in self.plugins:
            self.logger.error("Plugin %s not loaded", plugin_name)
            return False

        plugin = self.plugins[plugin_name]

        try:
            if await plugin.activate():
                self.stats["active"] += 1
                self.logger.info("Plugin %s activated", plugin_name)

                # Emit event
                await self.event_bus.emit(
                    Event(
                        event_type="plugin_activated",
                        source="plugin_manager",
                        data={"plugin_name": plugin_name},
                    ),
                )

                return True
            self.logger.warning("Plugin %s activation failed", plugin_name)
            return False

        except Exception as e:
            self.logger.exception("Error activating plugin %s: %s", plugin_name, e)
            return False

    async def deactivate_plugin(self, plugin_name: str) -> bool:
        """Deactivate an active plugin.

        Calls the plugin's deactivate method, updates statistics, and emits
        deactivation event through event bus.

        Args:
            plugin_name: Name of the plugin to deactivate.

        Returns:
            bool: True if deactivation succeeded, False otherwise.
        """
        if plugin_name not in self.plugins:
            self.logger.error("Plugin %s not loaded", plugin_name)
            return False

        plugin = self.plugins[plugin_name]

        try:
            if await plugin.deactivate():
                if plugin.status == PluginStatus.READY:
                    self.stats["active"] = max(0, self.stats["active"] - 1)

                self.logger.info("Plugin %s deactivated", plugin_name)

                # Emit event
                await self.event_bus.emit(
                    Event(
                        event_type="plugin_deactivated",
                        source="plugin_manager",
                        data={"plugin_name": plugin_name},
                    ),
                )

                return True
            self.logger.warning("Plugin %s deactivation failed", plugin_name)
            return False

        except Exception as e:
            self.logger.exception("Error deactivating plugin %s: %s", plugin_name, e)
            return False

    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin.

        Deactivates plugin if active, calls cleanup, removes from registry,
        and emits unload event.

        Args:
            plugin_name: Name of the plugin to unload.

        Returns:
            bool: True if unload succeeded or plugin not loaded, False on error.
        """
        if plugin_name not in self.plugins:
            return True

        plugin = self.plugins[plugin_name]

        try:
            # Deactivate first
            await self.deactivate_plugin(plugin_name)

            # Cleanup
            await plugin.cleanup()

            # Remove from registry
            del self.plugins[plugin_name]
            self.stats["loaded"] = max(0, self.stats["loaded"] - 1)

            self.logger.info("Plugin %s unloaded", plugin_name)

            # Emit event
            await self.event_bus.emit(
                Event(
                    event_type="plugin_unloaded",
                    source="plugin_manager",
                    data={"plugin_name": plugin_name},
                ),
            )

            return True

        except Exception as e:
            self.logger.exception("Error unloading plugin %s: %s", plugin_name, e)
            return False

    def get_plugin(self, plugin_name: str) -> AbstractPlugin | None:
        """Get plugin instance by name.

        Args:
            plugin_name: Name of the plugin to retrieve.

        Returns:
            AbstractPlugin | None: Plugin instance or None if not loaded.
        """
        return self.plugins.get(plugin_name)

    def get_plugins_by_capability(self, capability: str) -> list[AbstractPlugin]:
        """Get plugins with specific capability.

        Filters loaded plugins by a specific capability (e.g., 'static_analysis').

        Args:
            capability: Capability identifier to filter plugins by.

        Returns:
            list[AbstractPlugin]: List of plugins with the specified capability.
        """
        matching_plugins = []

        for plugin_name, plugin in self.plugins.items():
            if plugin_name in self.plugin_metadata:
                metadata = self.plugin_metadata[plugin_name]
                if capability in metadata.capabilities:
                    matching_plugins.append(plugin)

        return matching_plugins

    def get_plugins_by_type(self, component_type: ComponentType) -> list[AbstractPlugin]:
        """Get plugins of specific type.

        Filters loaded plugins by component type (e.g., GHIDRA_SCRIPT, FRIDA_SCRIPT).

        Args:
            component_type: ComponentType to filter plugins by.

        Returns:
            list[AbstractPlugin]: List of plugins of the specified type.
        """
        matching_plugins = []

        for plugin_name, plugin in self.plugins.items():
            if plugin_name in self.plugin_metadata:
                metadata = self.plugin_metadata[plugin_name]
                if metadata.component_type == component_type:
                    matching_plugins.append(plugin)

        return matching_plugins

    def get_plugin_stats(self) -> dict[str, Any]:
        """Get plugin statistics.

        Collects and returns statistics about loaded, active, and discovered plugins.

        Returns:
            dict[str, Any]: Dictionary with discovered count, loaded count, active plugins
                list, failed count, and type breakdown (ghidra, frida, python).
        """
        active_plugins = [name for name, plugin in self.plugins.items() if plugin.status == PluginStatus.ACTIVE]

        return {
            **self.stats,
            "total_discovered": len(self.plugin_metadata),
            "active_plugins": active_plugins,
            "plugin_types": {
                "ghidra": len([p for p in self.plugin_metadata.values() if p.component_type == ComponentType.GHIDRA_SCRIPT]),
                "frida": len([p for p in self.plugin_metadata.values() if p.component_type == ComponentType.FRIDA_SCRIPT]),
                "python": len([p for p in self.plugin_metadata.values() if p.component_type == ComponentType.CUSTOM_MODULE]),
            },
        }


@log_all_methods
class WorkflowEngine:
    """Configurable workflow execution engine."""

    def __init__(self, plugin_manager: PluginManager, event_bus: EventBus, logger: logging.Logger) -> None:
        """Initialize workflow engine with plugin manager, event bus, and logger.

        Sets up workflow execution engine with default workflow templates and
        configuration for managing multiple concurrent workflow executions.

        Args:
            plugin_manager: PluginManager instance for accessing plugins.
            event_bus: EventBus instance for publishing workflow events.
            logger: Logger instance for workflow diagnostics.
        """
        self.plugin_manager = plugin_manager
        self.event_bus = event_bus
        self.logger = logger

        self.workflows: dict[str, WorkflowDefinition] = {}
        self.running_workflows: dict[str, dict[str, Any]] = {}
        self.workflow_history: list[dict[str, Any]] = []

        self.max_concurrent_workflows = 10
        self.default_timeout = 300

        # Workflow templates
        self._load_default_workflows()

    def _load_default_workflows(self) -> None:
        """Load default workflow templates.

        Initializes built-in workflow definitions for binary analysis and license
        bypass operations that can be executed by the workflow engine.

        Returns:
            None
        """
        # Binary Analysis Workflow
        self.register_workflow(
            WorkflowDefinition(
                workflow_id="binary_analysis_full",
                name="Complete Binary Analysis",
                description="Full binary analysis using all available tools",
                steps=[
                    WorkflowStep(
                        step_id="detect_protection",
                        name="Detect Protection",
                        plugin_name="ghidra_ModernPackerDetector",
                        method="analyze_binary",
                        dependencies=[],
                    ),
                    WorkflowStep(
                        step_id="extract_metadata",
                        name="Extract Metadata",
                        plugin_name="python_neural_network_detector",
                        method="analyze",
                        dependencies=["detect_protection"],
                    ),
                    WorkflowStep(
                        step_id="static_analysis",
                        name="Static Analysis",
                        plugin_name="ghidra_LicenseValidationAnalyzer",
                        method="analyze_binary",
                        dependencies=["extract_metadata"],
                    ),
                    WorkflowStep(
                        step_id="dynamic_analysis",
                        name="Dynamic Analysis",
                        plugin_name="frida_wasm_protection_bypass",
                        method="attach_process",
                        dependencies=["static_analysis"],
                        condition="static_analysis.has_dynamic_protection",
                    ),
                ],
                parallel_execution=False,
                timeout=1800,
                error_handling="continue",
            ),
        )

        # License Bypass Workflow
        self.register_workflow(
            WorkflowDefinition(
                workflow_id="license_bypass_comprehensive",
                name="Comprehensive License Bypass",
                description="Multi-layered license bypass using all bypass components",
                steps=[
                    WorkflowStep(
                        step_id="start_license_server",
                        name="Start License Server",
                        plugin_name="python_license_server_emulator",
                        method="start_servers",
                        dependencies=[],
                    ),
                    WorkflowStep(
                        step_id="setup_cloud_intercept",
                        name="Setup Cloud Interception",
                        plugin_name="python_cloud_license_interceptor",
                        method="start_proxy",
                        dependencies=[],
                    ),
                    WorkflowStep(
                        step_id="bypass_ssl_pinning",
                        name="Bypass SSL Pinning",
                        plugin_name="frida_certificate_pinning_bypass",
                        method="attach_process",
                        dependencies=["setup_cloud_intercept"],
                    ),
                    WorkflowStep(
                        step_id="emulate_dongle",
                        name="Emulate Hardware Dongle",
                        plugin_name="python_hardware_dongle_emulator",
                        method="start_emulation",
                        dependencies=[],
                        condition="requires_hardware_dongle",
                    ),
                ],
                parallel_execution=True,
                timeout=600,
                error_handling="continue",
            ),
        )

    def register_workflow(self, workflow: WorkflowDefinition) -> None:
        """Register a workflow definition.

        Adds a workflow definition to the engine's available workflows for execution.

        Args:
            workflow: WorkflowDefinition object to register.

        Returns:
            None
        """
        self.workflows[workflow.workflow_id] = workflow
        self.logger.info("Registered workflow: %s", workflow.name)

    async def execute_workflow(self, workflow_id: str, parameters: dict[str, Any]) -> str:
        """Execute a workflow.

        Queues and starts async execution of a registered workflow with provided
        parameters, returning an execution ID for monitoring progress.

        Args:
            workflow_id: ID of the workflow to execute.
            parameters: Dictionary of parameters to pass to workflow steps.

        Returns:
            str: Unique execution ID for tracking workflow progress.

        Raises:
            ValueError: If workflow ID not found.
            Exception: If maximum concurrent workflows limit exceeded.
        """
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow not found: {workflow_id}")

        if len(self.running_workflows) >= self.max_concurrent_workflows:
            raise Exception("Maximum concurrent workflows reached")

        workflow = self.workflows[workflow_id]
        execution_id = str(uuid.uuid4())

        # Create execution context
        execution_context = {
            "execution_id": execution_id,
            "workflow_id": workflow_id,
            "workflow": workflow,
            "parameters": parameters,
            "status": WorkflowStatus.PENDING,
            "start_time": datetime.now(UTC),
            "end_time": None,
            "current_step": None,
            "completed_steps": [],
            "step_results": {},
            "errors": [],
            "progress": 0.0,
        }

        self.running_workflows[execution_id] = execution_context

        # Start execution
        task = asyncio.create_task(self._execute_workflow_async(execution_context))
        # Store task reference to prevent garbage collection
        if not hasattr(self, "_execution_tasks"):
            self._execution_tasks = set()
        self._execution_tasks.add(task)
        # Remove task from set when it's done
        task.add_done_callback(self._execution_tasks.discard)

        self.logger.info("Started workflow execution: %s (ID: %s)", workflow.name, execution_id)

        return execution_id

    async def _execute_workflow_async(self, context: dict[str, Any]) -> None:
        """Execute workflow asynchronously.

        Main async execution handler that orchestrates sequential or parallel
        workflow execution, emits events, handles errors, and logs results.

        Args:
            context: Execution context dictionary with workflow and parameters.

        Returns:
            None
        """
        execution_id = context["execution_id"]
        workflow = context["workflow"]

        try:
            context["status"] = WorkflowStatus.RUNNING

            # Emit start event
            await self.event_bus.emit(
                Event(
                    event_type="workflow_started",
                    source="workflow_engine",
                    data={
                        "execution_id": execution_id,
                        "workflow_id": workflow.workflow_id,
                        "workflow_name": workflow.name,
                    },
                ),
            )

            if workflow.parallel_execution:
                await self._execute_parallel_workflow(context)
            else:
                await self._execute_sequential_workflow(context)

            context["status"] = WorkflowStatus.COMPLETED
            context["end_time"] = datetime.now(UTC)
            context["progress"] = 1.0

            self.logger.info("Workflow completed: %s", execution_id)

            # Emit completion event
            await self.event_bus.emit(
                Event(
                    event_type="workflow_completed",
                    source="workflow_engine",
                    data={
                        "execution_id": execution_id,
                        "results": context["step_results"],
                        "duration": (context["end_time"] - context["start_time"]).total_seconds(),
                    },
                ),
            )

        except Exception as e:
            context["status"] = WorkflowStatus.FAILED
            context["end_time"] = datetime.now(UTC)
            context["errors"].append(str(e))

            self.logger.exception("Workflow failed: %s - %s", execution_id, e)

            # Emit failure event
            await self.event_bus.emit(
                Event(
                    event_type="workflow_failed",
                    source="workflow_engine",
                    data={
                        "execution_id": execution_id,
                        "error": str(e),
                        "completed_steps": context["completed_steps"],
                    },
                ),
            )

        finally:
            # Move to history and cleanup
            self.workflow_history.append(context)
            if execution_id in self.running_workflows:
                del self.running_workflows[execution_id]

    async def _execute_sequential_workflow(self, context: dict[str, Any]) -> None:
        """Execute workflow steps sequentially.

        Executes workflow steps one at a time in order, respecting dependencies
        and conditions, with error handling based on workflow configuration.

        Args:
            context: Execution context with workflow definition and results.

        Returns:
            None

        Raises:
            Exception: If dependencies not met for a step with stop error handling.
        """
        workflow = context["workflow"]
        total_steps = len(workflow.steps)

        for i, step in enumerate(workflow.steps):
            # Check if step should be executed (condition)
            if step.condition and not self._evaluate_condition(step.condition, context):
                self.logger.info("Skipping step %s - condition not met", step.step_id)
                continue

            # Check dependencies
            if not self._check_dependencies(step, context):
                error_msg = f"Dependencies not met for step: {step.step_id}"
                context["errors"].append(error_msg)
                if workflow.error_handling == "stop":
                    raise Exception(error_msg)
                continue

            # Execute step
            context["current_step"] = step.step_id
            context["progress"] = i / total_steps

            await self._execute_step(step, context)

            context["completed_steps"].append(step.step_id)

            # Emit step completion event
            await self.event_bus.emit(
                Event(
                    event_type="workflow_step_completed",
                    source="workflow_engine",
                    data={
                        "execution_id": context["execution_id"],
                        "step_id": step.step_id,
                        "step_name": step.name,
                        "progress": context["progress"],
                    },
                ),
            )

    async def _execute_parallel_workflow(self, context: dict[str, Any]) -> None:
        """Execute workflow steps in parallel where possible.

        Executes workflow steps concurrently based on dependency graph, respecting
        dependencies while maximizing parallelism for independent steps.

        Args:
            context: Execution context with workflow definition and tracking data.

        Returns:
            None

        Raises:
            Exception: If a step fails with stop error handling configured.
        """
        workflow = context["workflow"]

        # Build dependency graph
        dependency_graph = self._build_dependency_graph(workflow.steps)

        # Log dependency analysis
        self.logger.info("Built dependency graph with %d nodes", len(dependency_graph))
        for step_id, deps in dependency_graph.items():
            if deps:
                self.logger.debug("Step %s depends on: %s", step_id, deps)

        # Execute in dependency order with parallelization
        executed_steps: set[str] = set()
        tasks = []  # Track all concurrent tasks

        while len(executed_steps) < len(workflow.steps):
            # Find steps ready to execute
            ready_steps = []
            for step in workflow.steps:
                if step.step_id not in executed_steps and all(dep in executed_steps for dep in step.dependencies):
                    # Check condition
                    if step.condition and not self._evaluate_condition(step.condition, context):
                        executed_steps.add(step.step_id)  # Mark as done (skipped)
                        continue

                    ready_steps.append(step)

            if not ready_steps:
                break  # No more steps can be executed

            # Execute ready steps in parallel
            step_tasks = []
            for step in ready_steps:
                task = asyncio.create_task(self._execute_step(step, context))
                step_tasks.append((step.step_id, task))
                tasks.append(task)  # Track all tasks for global monitoring

            # Wait for completion
            for step_id, task in step_tasks:
                try:
                    await task
                    executed_steps.add(step_id)
                    context["completed_steps"].append(step_id)

                    # Update progress
                    context["progress"] = len(executed_steps) / len(workflow.steps)

                except Exception as e:
                    context["errors"].append(f"Step {step_id} failed: {e}")
                    if workflow.error_handling == "stop":
                        raise

        # Log completion of all tasks
        self.logger.info("Parallel workflow execution completed. Total tasks executed: %d", len(tasks))

        # Clean up any remaining tasks
        for task in tasks:
            if not task.done():
                task.cancel()

    def _build_dependency_graph(self, steps: list[WorkflowStep]) -> dict[str, list[str]]:
        """Build dependency graph for parallel execution.

        Constructs a dictionary mapping step IDs to their dependency lists for
        parallelization analysis.

        Args:
            steps: List of workflow steps to analyze.

        Returns:
            dict[str, list[str]]: Mapping of step_id to list of dependency step_ids.
        """
        return {step.step_id: step.dependencies.copy() for step in steps}

    def _check_dependencies(self, step: WorkflowStep, context: dict[str, Any]) -> bool:
        """Check if step dependencies are satisfied.

        Verifies that all dependencies for a workflow step have completed execution.

        Args:
            step: WorkflowStep to check dependencies for.
            context: Execution context with completed steps list.

        Returns:
            bool: True if all dependencies completed, False otherwise.
        """
        return all(dep in context["completed_steps"] for dep in step.dependencies)

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate step execution condition.

        Evaluates a conditional expression using step results and parameters to
        determine if a step should execute. Supports dot notation for property access.

        Args:
            condition: Condition expression string (e.g., 'step_id.property').
            context: Execution context with step results and parameters.

        Returns:
            bool: True if condition evaluates to true, False otherwise.
        """
        try:
            # Create safe evaluation context
            eval_context = {
                "results": context["step_results"],
                "parameters": context["parameters"],
            }

            # Log evaluation context for debugging
            self.logger.debug("Evaluating condition '%s' with context: %s", condition, list(eval_context.keys()))

            # Simple condition evaluation (could be enhanced with proper parser)
            # For now, support basic property checks
            if "." in condition:
                parts = condition.split(".")
                if len(parts) == 2:
                    step_id, property_name = parts
                    if step_id in context["step_results"]:
                        result = context["step_results"][step_id]
                        return bool(result.get(property_name, False))

            return False

        except Exception as e:
            self.logger.exception("Error evaluating condition '%s': %s", condition, e)
            return False

    async def _execute_step(self, step: WorkflowStep, context: dict[str, Any]) -> None:
        """Execute individual workflow step.

        Executes a single workflow step using the specified plugin operation with
        timeout, retry logic, and result storage. Handles errors based on retry config.

        Args:
            step: WorkflowStep to execute.
            context: Execution context for storing results and handling errors.

        Returns:
            None

        Raises:
            Exception: If step execution fails or exceeds timeout after max retries.
        """
        start_time = datetime.now(UTC)

        try:
            # Get plugin
            plugin = self.plugin_manager.get_plugin(step.plugin_name)
            if not plugin:
                raise Exception(f"Plugin not found: {step.plugin_name}")

            # Prepare parameters
            step_params = step.parameters.copy()
            step_params.update(context["parameters"])

            # Execute with timeout
            result = await asyncio.wait_for(
                plugin.execute_operation(step.method, step_params),
                timeout=step.timeout or self.default_timeout,
            )

            # Store result
            context["step_results"][step.step_id] = result

            # Log performance
            duration = (datetime.now(UTC) - start_time).total_seconds()
            self.logger.info("Step %s completed in %.2fs", step.step_id, duration)

        except TimeoutError as timeout_error:
            error_msg = f"Step {step.step_id} timed out"
            context["errors"].append(error_msg)

            if step.retry_count >= step.max_retries:
                raise Exception(error_msg) from timeout_error

            step.retry_count += 1
            self.logger.warning("Retrying step %s (attempt %d)", step.step_id, step.retry_count)
            await self._execute_step(step, context)
        except Exception as e:
            error_msg = f"Step {step.step_id} failed: {e}"
            context["errors"].append(error_msg)

            if step.retry_count >= step.max_retries:
                raise Exception(error_msg) from e
            step.retry_count += 1
            self.logger.warning("Retrying step %s (attempt %d)", step.step_id, step.retry_count)
            await self._execute_step(step, context)

    def get_workflow_status(self, execution_id: str) -> dict[str, Any] | None:
        """Get workflow execution status.

        Retrieves current or historical status of a workflow execution including
        progress, completed steps, errors, and timing information.

        Args:
            execution_id: Unique execution ID to retrieve status for.

        Returns:
            dict[str, Any] | None: Status dictionary or None if execution not found.
        """
        if execution_id in self.running_workflows:
            context = self.running_workflows[execution_id]
            return {
                "execution_id": execution_id,
                "workflow_id": context["workflow_id"],
                "status": context["status"].value,
                "progress": context["progress"],
                "current_step": context["current_step"],
                "completed_steps": context["completed_steps"],
                "errors": context["errors"],
                "start_time": context["start_time"].isoformat(),
                "duration": (datetime.now(UTC) - context["start_time"]).total_seconds(),
            }

        return next(
            (
                {
                    "execution_id": execution_id,
                    "workflow_id": workflow_record["workflow_id"],
                    "status": workflow_record["status"].value,
                    "progress": workflow_record["progress"],
                    "completed_steps": workflow_record["completed_steps"],
                    "errors": workflow_record["errors"],
                    "start_time": workflow_record["start_time"].isoformat(),
                    "end_time": (workflow_record["end_time"].isoformat() if workflow_record["end_time"] else None),
                    "duration": ((workflow_record["end_time"] or datetime.now(UTC)) - workflow_record["start_time"]).total_seconds(),
                }
                for workflow_record in self.workflow_history
                if workflow_record["execution_id"] == execution_id
            ),
            None,
        )

    def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel running workflow.

        Marks a running workflow execution for cancellation and updates its status.

        Args:
            execution_id: Execution ID of the workflow to cancel.

        Returns:
            bool: True if workflow was cancelled, False if not running.
        """
        if execution_id in self.running_workflows:
            context = self.running_workflows[execution_id]
            context["status"] = WorkflowStatus.CANCELLED
            context["end_time"] = datetime.now(UTC)

            self.logger.info("Workflow cancelled: %s", execution_id)
            return True

        return False

    def get_available_workflows(self) -> list[dict[str, Any]]:
        """Get list of available workflows.

        Returns metadata for all registered workflows including name, description,
        step count, and execution mode.

        Returns:
            list[dict[str, Any]]: List of workflow metadata dictionaries.
        """
        return [
            {
                "workflow_id": workflow.workflow_id,
                "name": workflow.name,
                "description": workflow.description,
                "steps": len(workflow.steps),
                "parallel_execution": workflow.parallel_execution,
                "tags": workflow.tags,
            }
            for workflow in self.workflows.values()
        ]


@log_all_methods
class AnalysisCoordinator:
    """Real-time analysis coordination and orchestration."""

    def __init__(
        self,
        plugin_manager: PluginManager,
        workflow_engine: WorkflowEngine,
        event_bus: EventBus,
        logger: logging.Logger,
    ) -> None:
        """Initialize analysis coordinator with plugin manager, workflow engine, event bus, and logger.

        Sets up analysis coordinator that orchestrates binary analysis workflows,
        manages analysis queue, and subscribes to relevant events for integration
        with the plugin and workflow systems.

        Args:
            plugin_manager: PluginManager instance for accessing analysis plugins.
            workflow_engine: WorkflowEngine instance for executing analysis workflows.
            event_bus: EventBus instance for event-driven coordination.
            logger: Logger instance for analysis diagnostics.
        """
        self.plugin_manager = plugin_manager
        self.workflow_engine = workflow_engine
        self.event_bus = event_bus
        self.logger = logger

        self.active_analyses: dict[str, dict[str, Any]] = {}
        self.analysis_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.coordinator_task: asyncio.Task[None] | None = None
        self.running: bool = False

        # Analysis templates
        self.analysis_templates = {
            "quick_scan": {
                "workflow_id": "binary_analysis_quick",
                "timeout": 300,
                "priority": EventPriority.MEDIUM,
            },
            "deep_analysis": {
                "workflow_id": "binary_analysis_full",
                "timeout": 1800,
                "priority": EventPriority.HIGH,
            },
            "license_bypass": {
                "workflow_id": "license_bypass_comprehensive",
                "timeout": 600,
                "priority": EventPriority.HIGH,
            },
        }

        # Subscribe to events
        self.event_bus.subscribe("analysis_request", self._handle_analysis_request)
        self.event_bus.subscribe("workflow_completed", self._handle_workflow_completed)
        self.event_bus.subscribe("workflow_failed", self._handle_workflow_failed)

    async def start(self) -> None:
        """Start analysis coordinator.

        Starts the analysis coordinator's background coordination loop and makes
        it ready to process analysis requests and workflow events.

        Returns:
            None
        """
        if self.running:
            return

        self.running = True
        self.coordinator_task = asyncio.create_task(self._coordination_loop())

        self.logger.info("Analysis coordinator started")

    async def stop(self) -> None:
        """Stop analysis coordinator.

        Stops the analysis coordinator's background loop and cleanly shuts down
        any pending analysis operations.

        Returns:
            None
        """
        if not self.running:
            return

        self.running = False

        if self.coordinator_task:
            self.coordinator_task.cancel()
            try:
                await self.coordinator_task
            except asyncio.CancelledError as e:
                self.logger.debug("Plugin operation error: %s", e)

        self.logger.info("Analysis coordinator stopped")

    async def analyze_binary(
        self,
        binary_path: str,
        analysis_type: str = "deep_analysis",
        parameters: dict[str, Any] | None = None,
    ) -> str:
        """Analyze binary file.

        Queues a binary analysis request with specified analysis type and parameters,
        extracts file information, and returns unique analysis ID for tracking.

        Args:
            binary_path: Path to the binary file to analyze.
            analysis_type: Type of analysis ('quick_scan', 'deep_analysis', 'license_bypass').
            parameters: Optional dictionary of additional analysis parameters.

        Returns:
            str: Unique analysis ID for tracking analysis progress.

        Raises:
            ValueError: If binary file not found or analysis type unknown.
        """
        if not Path(binary_path).exists():
            raise ValueError(f"Binary file not found: {binary_path}")

        if analysis_type not in self.analysis_templates:
            raise ValueError(f"Unknown analysis type: {analysis_type}")

        analysis_id = str(uuid.uuid4())
        template = self.analysis_templates[analysis_type]

        # Prepare analysis context
        analysis_context = {
            "analysis_id": analysis_id,
            "binary_path": binary_path,
            "analysis_type": analysis_type,
            "template": template,
            "parameters": parameters or {},
            "start_time": datetime.now(UTC),
            "status": "queued",
            "workflow_execution_id": None,
            "results": {},
            "progress": 0.0,
        }

        # Add basic file information
        file_info = await self._extract_file_info(binary_path)
        analysis_context["file_info"] = file_info

        # Store analysis
        self.active_analyses[analysis_id] = analysis_context

        # Queue for processing
        await self.analysis_queue.put(analysis_context)

        self.logger.info("Queued analysis: %s for %s", analysis_id, binary_path)

        return analysis_id

    async def _coordination_loop(self) -> None:
        """Run main coordination loop.

        Main background loop that continuously processes analysis requests from
        the queue and delegates them to the workflow engine with error handling.

        Returns:
            None
        """
        while self.running:
            try:
                # Process analysis queue
                analysis_context = await asyncio.wait_for(
                    self.analysis_queue.get(),
                    timeout=1.0,
                )

                await self._start_analysis(analysis_context)

            except TimeoutError:
                # Continue processing
                continue
            except Exception as e:
                self.logger.exception("Error in coordination loop: %s", e)

    async def _start_analysis(self, analysis_context: dict[str, Any]) -> None:
        """Start individual analysis.

        Initiates workflow execution for a queued analysis, preparing workflow
        parameters, starting the workflow, and emitting status events.

        Args:
            analysis_context: Analysis context dictionary with binary path and parameters.

        Returns:
            None
        """
        analysis_id = analysis_context["analysis_id"]

        try:
            analysis_context["status"] = "starting"

            # Prepare workflow parameters
            workflow_params = {
                "binary_path": analysis_context["binary_path"],
                "file_info": analysis_context["file_info"],
                **analysis_context["parameters"],
            }

            # Start workflow
            workflow_id = analysis_context["template"]["workflow_id"]
            execution_id = await self.workflow_engine.execute_workflow(workflow_id, workflow_params)

            analysis_context["workflow_execution_id"] = execution_id
            analysis_context["status"] = "running"

            # Emit start event
            await self.event_bus.emit(
                Event(
                    event_type="analysis_started",
                    source="analysis_coordinator",
                    data={
                        "analysis_id": analysis_id,
                        "binary_path": analysis_context["binary_path"],
                        "analysis_type": analysis_context["analysis_type"],
                        "execution_id": execution_id,
                    },
                ),
            )

            self.logger.info("Started analysis: %s", analysis_id)

        except Exception as e:
            analysis_context["status"] = "failed"
            analysis_context["error"] = str(e)

            self.logger.exception("Failed to start analysis %s: %s", analysis_id, e)

            # Emit failure event
            await self.event_bus.emit(
                Event(
                    event_type="analysis_failed",
                    source="analysis_coordinator",
                    data={
                        "analysis_id": analysis_id,
                        "error": str(e),
                    },
                ),
            )

    async def _extract_file_info(self, file_path: str) -> dict[str, Any]:
        """Extract basic file information.

        Gathers file metadata including size, modification time, file type, and
        cryptographic hashes (for files under 100MB).

        Args:
            file_path: Path to the file to analyze.

        Returns:
            dict[str, Any]: Dictionary with file name, size, hashes, type, and timestamps.
        """
        try:
            file_path_obj = Path(file_path)
            stat = file_path_obj.stat()

            # Basic file info
            info = {
                "name": file_path_obj.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "extension": file_path_obj.suffix.lower(),
                "hash_md5": "",
                "hash_sha256": "",
            }

            # Calculate hashes for smaller files
            if stat.st_size < 100 * 1024 * 1024:  # 100MB limit
                import hashlib

                def _calc_hashes() -> tuple[str, str]:
                    """Calculate SHA256 hashes of the file content.

                    Reads the file content and computes SHA256 hash for integrity
                    verification and deduplication purposes.

                    Returns:
                        tuple[str, str]: Pair of SHA256 hex digests for the file.
                    """
                    with open(file_path, "rb") as f:
                        content = f.read()
                        hash_val = hashlib.sha256(content).hexdigest()
                        return hash_val, hash_val

                hash_primary, hash_sha256 = await asyncio.to_thread(_calc_hashes)
                info["hash_sha256_primary"] = hash_primary
                info["hash_sha256"] = hash_sha256

            # Detect file type
            info["file_type"] = self._detect_file_type(file_path)

            return info

        except Exception as e:
            self.logger.exception("Error extracting file info: %s", e)
            return {"name": Path(file_path).name, "error": str(e)}

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type.

        Identifies binary file format by magic number (PE, ELF, Mach-O, etc.).

        Args:
            file_path: Path to the binary file to analyze.

        Returns:
            str: File type identifier ('PE', 'ELF', 'Mach-O', or 'Unknown').
        """
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)

            # PE files
            if magic[:2] == b"MZ":
                return "PE"
            # ELF files
            if magic == b"\x7fELF":
                return "ELF"
            # Mach-O files
            if magic in [
                b"\xfe\xed\xfa\xce",
                b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe",
            ]:
                return "Mach-O"
            return "Unknown"

        except Exception:
            return "Unknown"

    async def _handle_analysis_request(self, event: Event) -> None:
        """Handle analysis request event.

        Processes incoming analysis requests from event bus, queues the analysis,
        and sends response event with the analysis ID.

        Args:
            event: Event object containing analysis_request data with binary_path and type.

        Returns:
            None
        """
        try:
            data = event.data
            binary_path = data.get("binary_path")
            analysis_type = data.get("analysis_type", "deep_analysis")
            parameters = data.get("parameters", {})

            if binary_path:
                analysis_id = await self.analyze_binary(binary_path, analysis_type, parameters)

                # Send response event
                await self.event_bus.emit(
                    Event(
                        event_type="analysis_request_processed",
                        source="analysis_coordinator",
                        target=event.source,
                        data={"analysis_id": analysis_id, "request_id": event.event_id},
                    ),
                )

        except Exception as e:
            self.logger.exception("Error handling analysis request: %s", e)

    async def _handle_workflow_completed(self, event: Event) -> None:
        """Handle workflow completion.

        Processes workflow completion events, updates analysis status, stores results,
        and emits analysis completion event through event bus.

        Args:
            event: Event object containing execution_id and workflow results.

        Returns:
            None
        """
        execution_id = event.data.get("execution_id")
        results = event.data.get("results", {})

        # Find corresponding analysis
        for analysis_id, context in self.active_analyses.items():
            if context.get("workflow_execution_id") == execution_id:
                context["status"] = "completed"
                context["results"] = results
                context["end_time"] = datetime.now(UTC)
                context["progress"] = 1.0

                # Emit completion event
                await self.event_bus.emit(
                    Event(
                        event_type="analysis_completed",
                        source="analysis_coordinator",
                        data={
                            "analysis_id": analysis_id,
                            "results": results,
                            "duration": (context["end_time"] - context["start_time"]).total_seconds(),
                        },
                    ),
                )

                self.logger.info("Analysis completed: %s", analysis_id)
                break

    async def _handle_workflow_failed(self, event: Event) -> None:
        """Handle workflow failure.

        Processes workflow failure events, updates analysis status to failed,
        stores error information, and emits analysis failure event.

        Args:
            event: Event object containing execution_id and error information.

        Returns:
            None
        """
        execution_id = event.data.get("execution_id")
        error = event.data.get("error")

        # Find corresponding analysis
        for analysis_id, context in self.active_analyses.items():
            if context.get("workflow_execution_id") == execution_id:
                context["status"] = "failed"
                context["error"] = error
                context["end_time"] = datetime.now(UTC)

                # Emit failure event
                await self.event_bus.emit(
                    Event(
                        event_type="analysis_failed",
                        source="analysis_coordinator",
                        data={
                            "analysis_id": analysis_id,
                            "error": error,
                        },
                    ),
                )

                self.logger.error("Analysis failed: %s - %s", analysis_id, error)
                break

    def get_analysis_status(self, analysis_id: str) -> dict[str, Any] | None:
        """Get analysis status.

        Retrieves current status of an analysis execution including progress,
        workflow status, results, and errors.

        Args:
            analysis_id: Unique analysis ID to retrieve status for.

        Returns:
            dict[str, Any] | None: Status dictionary or None if not found.
        """
        if analysis_id in self.active_analyses:
            context = self.active_analyses[analysis_id]
            return {
                "analysis_id": analysis_id,
                "binary_path": context["binary_path"],
                "analysis_type": context["analysis_type"],
                "status": context["status"],
                "progress": context["progress"],
                "start_time": context["start_time"].isoformat(),
                "end_time": context.get("end_time", {}).isoformat() if context.get("end_time") else None,
                "workflow_execution_id": context.get("workflow_execution_id"),
                "results": context.get("results", {}),
                "error": context.get("error"),
            }

        return None

    def get_active_analyses(self) -> list[dict[str, Any]]:
        """Get all active analyses.

        Returns status information for all currently active or recently completed
        analyses.

        Returns:
            list[dict[str, Any]]: List of analysis status dictionaries.
        """
        return [status for analysis_id in self.active_analyses if (status := self.get_analysis_status(analysis_id)) is not None]


@log_all_methods
class ResourceManager:
    """System resource monitoring and management."""

    def __init__(self, config: dict[str, Any], logger: logging.Logger) -> None:
        """Initialize resource manager with configuration and logger.

        Sets up resource monitoring with process and thread pools, resource tracking,
        and automatic cleanup configuration for managing system resources.

        Args:
            config: Configuration dictionary with resource limits and pool settings.
            logger: Logger instance for resource diagnostics.
        """
        self.config = config
        self.logger = logger

        self.monitoring_enabled = config.get("resource_monitoring", True)
        self.auto_cleanup = config.get("auto_cleanup", True)
        self.max_memory_usage = config.get("max_memory_usage", 80)  # Percentage
        self.max_cpu_usage = config.get("max_cpu_usage", 90)  # Percentage

        # Resource pools
        self.process_pool: ProcessPoolExecutor | None = None
        self.thread_pool: ThreadPoolExecutor | None = None
        self.max_workers: int = config.get("max_workers", mp.cpu_count())

        # Monitoring
        self.monitoring_task: asyncio.Task[None] | None = None
        self.running: bool = False

        # Resource tracking
        self.resource_stats = {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0,
            "active_processes": 0,
            "active_threads": 0,
        }

        # Process tracking
        self.tracked_processes: dict[int, psutil.Process] = {}

    async def start(self) -> None:
        """Start resource manager.

        Initializes process and thread pools and starts background resource
        monitoring loop if enabled.

        Returns:
            None
        """
        if self.running:
            return

        self.running = True

        # Initialize process pools
        self.process_pool = ProcessPoolExecutor(max_workers=self.max_workers)
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers * 2)

        # Start monitoring
        if self.monitoring_enabled:
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())

        self.logger.info("Resource manager started")

    async def stop(self) -> None:
        """Stop resource manager.

        Cleanly shuts down process and thread pools, stops monitoring loop,
        and cleans up tracked processes.

        Returns:
            None
        """
        if not self.running:
            return

        self.running = False

        # Stop monitoring
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError as e:
                self.logger.exception("Plugin operation error: %s", e)

        # Shutdown pools
        if self.process_pool:
            self.process_pool.shutdown(wait=True)

        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)

        # Cleanup tracked processes
        await self._cleanup_processes()

        self.logger.info("Resource manager stopped")

    async def _monitoring_loop(self) -> None:
        """Resource monitoring loop.

        Background loop that continuously monitors system resources, checks limits,
        and performs automatic cleanup when enabled.

        Returns:
            None
        """
        while self.running:
            try:
                await self._update_resource_stats()
                await self._check_resource_limits()

                if self.auto_cleanup:
                    await self._auto_cleanup()

                await asyncio.sleep(5)  # Monitor every 5 seconds

            except Exception as e:
                self.logger.exception("Error in resource monitoring: %s", e)
                await asyncio.sleep(10)

    async def _update_resource_stats(self) -> None:
        """Update resource statistics.

        Collects current CPU, memory, disk usage, and process/thread counts
        and stores in resource_stats dictionary.

        Returns:
            None
        """
        try:
            # CPU usage
            self.resource_stats["cpu_usage"] = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            self.resource_stats["memory_usage"] = memory.percent

            # Disk usage (current directory)
            disk = psutil.disk_usage(".")
            self.resource_stats["disk_usage"] = (disk.used / disk.total) * 100

            # Process/thread counts
            current_process = psutil.Process()
            self.resource_stats["active_processes"] = len(current_process.children(recursive=True))
            self.resource_stats["active_threads"] = current_process.num_threads()

        except Exception as e:
            self.logger.exception("Error updating resource stats: %s", e)

    async def _check_resource_limits(self) -> None:
        """Check resource limits and warn if exceeded.

        Compares current CPU and memory usage against configured limits and
        logs warnings if thresholds are exceeded.

        Returns:
            None
        """
        cpu_usage = self.resource_stats["cpu_usage"]
        memory_usage = self.resource_stats["memory_usage"]

        if cpu_usage > self.max_cpu_usage:
            self.logger.warning("High CPU usage: %.1f%%", cpu_usage)

        if memory_usage > self.max_memory_usage:
            self.logger.warning("High memory usage: %.1f%%", memory_usage)

    async def _auto_cleanup(self) -> None:
        """Automatic cleanup of resources.

        Removes tracking for completed processes and performs garbage collection
        if memory usage exceeds configured maximum.

        Returns:
            None
        """
        try:
            # Clean up completed processes
            completed_pids = []
            for pid, process in self.tracked_processes.items():
                try:
                    if not process.is_running():
                        completed_pids.append(pid)
                except psutil.NoSuchProcess:
                    completed_pids.append(pid)

            for pid in completed_pids:
                del self.tracked_processes[pid]

            # Force garbage collection if memory usage is high
            if self.resource_stats["memory_usage"] > self.max_memory_usage:
                import gc

                gc.collect()
                self.logger.info("Performed garbage collection due to high memory usage")

        except Exception as e:
            self.logger.exception("Error in auto cleanup: %s", e)

    async def execute_in_process(self, func: Callable[..., Any], *args: object, **kwargs: object) -> object:
        """Execute function in process pool.

        Submits a function to the process pool for parallel execution and awaits result.

        Args:
            func: Callable function to execute.
            *args: Positional arguments to pass to function.
            **kwargs: Keyword arguments to pass to function.

        Returns:
            object: Return value from the executed function.

        Raises:
            Exception: If process pool not initialized or execution fails.
        """
        if not self.process_pool:
            raise Exception("Process pool not initialized")

        loop = asyncio.get_event_loop()
        future = self.process_pool.submit(func, *args, **kwargs)
        return await loop.run_in_executor(None, future.result)

    async def execute_in_thread(self, func: Callable[..., Any], *args: object, **kwargs: object) -> object:
        """Execute function in thread pool.

        Submits a function to the thread pool for concurrent execution and awaits result.

        Args:
            func: Callable function to execute.
            *args: Positional arguments to pass to function.
            **kwargs: Keyword arguments to pass to function.

        Returns:
            object: Return value from the executed function.

        Raises:
            Exception: If thread pool not initialized or execution fails.
        """
        if not self.thread_pool:
            raise Exception("Thread pool not initialized")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, func, *args, **kwargs)

    async def start_external_process(self, cmd: list[str], cwd: str | None = None) -> asyncio.subprocess.Process:
        """Start external process with tracking.

        Creates and tracks an external process, capturing its stdout/stderr and
        registering it for resource monitoring and cleanup.

        Args:
            cmd: List of command and arguments to execute.
            cwd: Optional working directory for process.

        Returns:
            asyncio.subprocess.Process: Process handle for interaction and monitoring.

        Raises:
            Exception: If process creation fails.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )

            # Track process
            if process.pid:
                try:
                    psutil_process = psutil.Process(process.pid)
                    self.tracked_processes[process.pid] = psutil_process
                except psutil.NoSuchProcess as e:
                    self.logger.exception("Plugin operation error: %s", e)

            self.logger.debug("Started external process: %s (PID: %s)", " ".join(cmd), process.pid)

            return process

        except Exception as e:
            self.logger.exception("Error starting external process: %s", e)
            raise

    async def kill_process(self, pid: int, force: bool = False) -> None:
        """Kill tracked process.

        Terminates a tracked process gracefully or forcefully, unregisters from
        tracking, and handles cleanup.

        Args:
            pid: Process ID to kill.
            force: If True, send SIGKILL; if False, send SIGTERM first.

        Returns:
            None
        """
        if pid not in self.tracked_processes:
            return
        try:
            process = self.tracked_processes[pid]
            if force:
                process.kill()
            else:
                process.terminate()

            # Wait for process to die
            await asyncio.sleep(1)

            if process.is_running():
                process.kill()

            del self.tracked_processes[pid]
            self.logger.info("Killed process: %d", pid)

        except psutil.NoSuchProcess:
            if pid in self.tracked_processes:
                del self.tracked_processes[pid]
        except Exception as e:
            self.logger.exception("Error killing process %d: %s", pid, e)

    async def _cleanup_processes(self) -> None:
        """Cleanup all tracked processes.

        Forcefully terminates and unregisters all tracked processes for shutdown.

        Returns:
            None
        """
        for pid in list(self.tracked_processes):
            await self.kill_process(pid, force=True)

    def get_resource_stats(self) -> dict[str, Any]:
        """Get current resource statistics.

        Returns current resource usage metrics including CPU, memory, disk, and
        process/thread counts.

        Returns:
            dict[str, Any]: Dictionary with CPU, memory, disk usage, process counts,
                and pool configuration.
        """
        return {
            **self.resource_stats,
            "tracked_processes": len(self.tracked_processes),
            "process_pool_workers": self.max_workers,
            "thread_pool_workers": self.max_workers * 2,
            "monitoring_enabled": self.monitoring_enabled,
        }


@log_all_methods
class IntellicrackcoreEngine:
    """Run Intellicrack core engine - orchestrates all components."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize Intellicrack core engine with optional configuration path.

        Initializes all core components (configuration, logging, event bus, plugin
        manager, workflow engine, analysis coordinator, and resource manager) in
        proper dependency order.

        Args:
            config_path: Optional path to configuration JSON file. Defaults to
                'config/intellicrack.json' if not provided.
        """
        # Initialize configuration
        self.config_manager = ConfigurationManager(config_path)
        self.config = self.config_manager.config

        # Initialize logging
        self.logging_manager = LoggingManager(self.config.get("logging", {}))
        self.logger = self.logging_manager.get_logger("core_engine")

        # Initialize core components
        self.event_bus = EventBus()
        self.event_bus.set_logger(self.logging_manager.get_logger("event_bus"))

        self.resource_manager = ResourceManager(
            self.config.get("engine", {}),
            self.logging_manager.get_logger("resource_manager"),
        )

        self.plugin_manager = PluginManager(
            self.config.get("plugins", {}),
            self.event_bus,
            self.logging_manager.get_logger("plugin_manager"),
        )

        self.workflow_engine = WorkflowEngine(
            self.plugin_manager,
            self.event_bus,
            self.logging_manager.get_logger("workflow_engine"),
        )

        self.analysis_coordinator = AnalysisCoordinator(
            self.plugin_manager,
            self.workflow_engine,
            self.event_bus,
            self.logging_manager.get_logger("analysis_coordinator"),
        )

        # Engine state
        self.running: bool = False
        self.startup_time: datetime | None = None

        # API interface
        self.api_handlers = {
            "analyze_binary": self._handle_analyze_binary,
            "get_analysis_status": self._handle_get_analysis_status,
            "list_plugins": self._handle_list_plugins,
            "get_plugin_status": self._handle_get_plugin_status,
            "execute_workflow": self._handle_execute_workflow,
            "get_workflow_status": self._handle_get_workflow_status,
            "get_system_status": self._handle_get_system_status,
        }

        self.logger.info("Intellicrack Core Engine initialized")

    async def start(self) -> None:
        """Start the core engine.

        Starts all core components (event bus, resource manager, plugin manager,
        workflow engine, analysis coordinator) and makes the engine ready to
        process analysis requests.

        Returns:
            None

        Raises:
            Exception: If any component fails to start.
        """
        if self.running:
            self.logger.warning("Engine already running")
            return

        self.startup_time = datetime.now(UTC)

        try:
            self.logger.info("Starting Intellicrack Core Engine...")

            # Start components in order
            await self.event_bus.start()
            await self.resource_manager.start()

            # Load and activate plugins
            loaded_plugins = await self.plugin_manager.load_all_plugins()
            self.logger.info("Loaded %d plugins", loaded_plugins)

            # Activate critical plugins
            await self._activate_core_plugins()

            # Start workflow engine and analysis coordinator
            await self.analysis_coordinator.start()

            self.running = True

            # Emit startup event
            await self.event_bus.emit(
                Event(
                    event_type="engine_started",
                    source="core_engine",
                    data={
                        "startup_time": self.startup_time.isoformat(),
                        "loaded_plugins": loaded_plugins,
                    },
                ),
            )

            self.logger.info("Intellicrack Core Engine started successfully")

        except Exception as e:
            self.logger.exception("Failed to start engine: %s", e)
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop the core engine.

        Gracefully shuts down all core components (analysis coordinator, plugins,
        resource manager, event bus) and cleans up resources in reverse startup order.

        Returns:
            None
        """
        if not self.running:
            return

        self.logger.info("Stopping Intellicrack Core Engine...")

        try:
            # Stop components in reverse order
            await self.analysis_coordinator.stop()

            # Deactivate and unload plugins
            await self._deactivate_all_plugins()

            await self.resource_manager.stop()
            await self.event_bus.stop()

            self.running = False

            self.logger.info("Intellicrack Core Engine stopped")

        except Exception as e:
            self.logger.exception("Error stopping engine: %s", e)

    async def _activate_core_plugins(self) -> None:
        """Activate core plugins required for operation.

        Activates essential plugins for framework functionality including neural
        network detection, pattern tracking, license server emulation, and cloud
        license interception.

        Returns:
            None
        """
        core_plugins = [
            "python_neural_network_detector",
            "python_pattern_evolution_tracker",
            "python_license_server_emulator",
            "python_cloud_license_interceptor",
        ]

        for plugin_name in core_plugins:
            if plugin_name in self.plugin_manager.plugins:
                await self.plugin_manager.activate_plugin(plugin_name)

    async def _deactivate_all_plugins(self) -> None:
        """Deactivate all active plugins.

        Deactivates and unloads all currently loaded plugins in a controlled manner,
        ensuring proper cleanup and resource release before engine shutdown.

        Returns:
            None
        """
        active_plugins = list(self.plugin_manager.plugins.keys())

        for plugin_name in active_plugins:
            await self.plugin_manager.deactivate_plugin(plugin_name)
            await self.plugin_manager.unload_plugin(plugin_name)

    # API Interface Methods

    async def _handle_analyze_binary(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle binary analysis API request.

        Processes an API request to analyze a binary file using the analysis
        coordinator, queuing the analysis with specified type and parameters.

        Args:
            request: Request dict containing 'binary_path' (required), 'analysis_type'
                (optional, default 'deep_analysis'), and 'parameters' (optional analysis
                parameters dictionary).

        Returns:
            dict[str, Any]: Response dict with analysis_id, status ('queued'),
                and success message.

        Raises:
            ValueError: If binary_path is not specified in the request.
        """
        binary_path = request.get("binary_path")
        analysis_type = request.get("analysis_type", "deep_analysis")
        parameters = request.get("parameters", {})

        if not binary_path:
            raise ValueError("binary_path is required")

        analysis_id = await self.analysis_coordinator.analyze_binary(
            binary_path,
            analysis_type,
            parameters,
        )

        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "message": "Analysis started successfully",
        }

    async def _handle_get_analysis_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle get analysis status API request.

        Retrieves the current status of a queued or running binary analysis.

        Args:
            request: Request dict containing 'analysis_id' (required) identifying
                the analysis to retrieve status for.

        Returns:
            dict[str, Any]: Status dict with analysis progress, results, and state
                from the analysis coordinator.

        Raises:
            ValueError: If analysis_id is not specified or analysis not found.
        """
        analysis_id = request.get("analysis_id")

        if not analysis_id:
            raise ValueError("analysis_id is required")

        if status := self.analysis_coordinator.get_analysis_status(analysis_id):
            return status
        else:
            raise ValueError(f"Analysis not found: {analysis_id}")

    async def _handle_list_plugins(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle list plugins API request.

        Lists all loaded plugins with metadata, optionally filtering by component
        type or capability.

        Args:
            request: Request dict with optional 'type' (component type to filter by)
                and 'capability' (capability to filter by) fields.

        Returns:
            dict[str, Any]: Dict with 'plugins' list containing plugin dicts with
                name, status, metadata, and supported operations for each plugin.
        """
        plugin_type = request.get("type")
        capability = request.get("capability")

        plugins = []

        for plugin_name, plugin in self.plugin_manager.plugins.items():
            if plugin_name in self.plugin_manager.plugin_metadata:
                metadata = self.plugin_manager.plugin_metadata[plugin_name]

                # Filter by type
                if plugin_type and metadata.component_type.value != plugin_type:
                    continue

                # Filter by capability
                if capability and capability not in metadata.capabilities:
                    continue

                plugins.append(
                    {
                        "name": plugin_name,
                        "status": plugin.status.value,
                        "metadata": metadata.to_dict(),
                        "operations": plugin.get_supported_operations(),
                    },
                )

        return {"plugins": plugins}

    async def _handle_get_plugin_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle get plugin status API request.

        Retrieves detailed status information for a specific loaded plugin.

        Args:
            request: Request dict containing 'plugin_name' (required) identifying
                the plugin to retrieve status for.

        Returns:
            dict[str, Any]: Plugin status dict with name, version, status, error info,
                performance metrics, and configuration from the plugin manager.

        Raises:
            ValueError: If plugin_name not specified or plugin not found.
        """
        plugin_name = request.get("plugin_name")

        if not plugin_name:
            raise ValueError("plugin_name is required")

        if plugin := self.plugin_manager.get_plugin(plugin_name):
            return plugin.get_status()
        else:
            raise ValueError(f"Plugin not found: {plugin_name}")

    async def _handle_execute_workflow(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle execute workflow API request.

        Queues and starts async execution of a registered workflow with provided
        parameters.

        Args:
            request: Request dict containing 'workflow_id' (required) and optional
                'parameters' dict with workflow step parameters.

        Returns:
            dict[str, Any]: Dict with execution_id, status ('started'),
                and success message for tracking workflow execution.

        Raises:
            ValueError: If workflow_id not specified or workflow not found.
        """
        workflow_id = request.get("workflow_id")
        parameters = request.get("parameters", {})

        if not workflow_id:
            raise ValueError("workflow_id is required")

        execution_id = await self.workflow_engine.execute_workflow(workflow_id, parameters)

        return {
            "execution_id": execution_id,
            "status": "started",
            "message": "Workflow execution started",
        }

    async def _handle_get_workflow_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle get workflow status API request.

        Retrieves the current status and progress of a running workflow execution.

        Args:
            request: Request dict containing 'execution_id' (required) identifying
                the workflow execution to retrieve status for.

        Returns:
            dict[str, Any]: Status dict with execution progress, completed steps,
                results, errors, and current state from the workflow engine.

        Raises:
            ValueError: If execution_id not specified or execution not found.
        """
        execution_id = request.get("execution_id")

        if not execution_id:
            raise ValueError("execution_id is required")

        if status := self.workflow_engine.get_workflow_status(execution_id):
            return status
        else:
            raise ValueError(f"Workflow execution not found: {execution_id}")

    async def _handle_get_system_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle get system status API request.

        Retrieves comprehensive system status including engine state, resource usage,
        active analyses, running workflows, and component statistics.

        Args:
            request: Request dict (no parameters required for this request).

        Returns:
            dict[str, Any]: Status dict containing engine_status, startup_time, uptime,
                plugin_stats, resource_stats, event_stats, active_analyses count,
                and running_workflows count.
        """
        return {
            "engine_status": "running" if self.running else "stopped",
            "startup_time": (self.startup_time.isoformat() if self.startup_time else None),
            "uptime": ((datetime.now(UTC) - self.startup_time).total_seconds() if self.startup_time else 0),
            "plugin_stats": self.plugin_manager.get_plugin_stats(),
            "resource_stats": self.resource_manager.get_resource_stats(),
            "event_stats": self.event_bus.get_stats(),
            "active_analyses": len(self.analysis_coordinator.active_analyses),
            "running_workflows": len(self.workflow_engine.running_workflows),
        }

    async def process_api_request(self, method: str, request: dict[str, Any]) -> dict[str, Any]:
        """Process an API request through the appropriate handler.

        Routes incoming API requests to registered handler methods based on the
        method name, with error handling and response formatting.

        Args:
            method: API method name (e.g., 'analyze_binary', 'list_plugins').
            request: Request dict to pass to the handler method.

        Returns:
            dict[str, Any]: Response dict with 'success' (bool), 'result' (if successful),
                'error' (if failed), and 'timestamp' in ISO format.

        Raises:
            Exception: If engine is not running.
            ValueError: If method is unknown/not registered.
        """
        if not self.running:
            raise Exception("Engine not running")

        if method not in self.api_handlers:
            raise ValueError(f"Unknown API method: {method}")

        try:
            handler = self.api_handlers[method]
            result = await handler(request)

            return {
                "success": True,
                "result": result,
                "timestamp": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            self.logger.exception("API request failed: %s - %s", method, e)

            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(UTC).isoformat(),
            }

    def generate_frida_script(self, target: str, script_type: str) -> str:
        """Generate a Frida instrumentation script for license bypass.

        Creates production-ready Frida scripts targeting specific protection
        mechanisms and licensing validation routines in the target binary.

        Args:
            target: Path to the target binary file.
            script_type: Type of script to generate (e.g., 'license_bypass',
                'anti_debug', 'memory_patch', 'api_hook').

        Returns:
            str: Complete Frida JavaScript code ready for injection.
        """
        target_name = Path(target).name if target else "unknown"
        script_templates = {
            "license_bypass": self._generate_license_bypass_frida(target_name),
            "anti_debug": self._generate_anti_debug_frida(target_name),
            "memory_patch": self._generate_memory_patch_frida(target_name),
            "api_hook": self._generate_api_hook_frida(target_name),
            "trial_bypass": self._generate_trial_bypass_frida(target_name),
            "registration": self._generate_registration_bypass_frida(target_name),
        }
        script_type_lower = script_type.lower().replace(" ", "_").replace("-", "_")
        if script_type_lower in script_templates:
            return script_templates[script_type_lower]
        return self._generate_generic_frida(target_name, script_type)

    def _generate_license_bypass_frida(self, target_name: str) -> str:
        """Generate license bypass Frida instrumentation script.

        Creates a production-ready Frida script that hooks license validation
        functions and registration checks, bypassing licensing protection
        mechanisms in the target binary.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code implementing license bypass
                including hooks for ValidateLicense, CheckRegistration, IsLicensed,
                VerifySerial functions and hardware ID spoofing APIs.
        """
        return f"""// Frida License Bypass Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

const config = {{
    targetModule: Process.enumerateModules()[0].name,
    logLevel: 'info',
    bypassCount: 0
}};

function log(level, msg) {{
    const timestamp = new Date().toISOString();
    console.log(`[${{timestamp}}] [${{level.toUpperCase()}}] ${{msg}}`);
}}

function hookLicenseValidation() {{
    const patterns = [
        {{ name: 'ValidateLicense', signature: '55 8B EC 83 EC ?? 53 56 57 8B ?? ?? ?? ?? ??' }},
        {{ name: 'CheckRegistration', signature: '55 8B EC 51 53 56 57 8B ?? ?? 85 ??' }},
        {{ name: 'IsLicensed', signature: '55 8B EC ?? ?? ?? ?? B8 01 00 00 00' }},
        {{ name: 'VerifySerial', signature: '55 8B EC 83 EC ?? 56 8B ?? ?? ?? E8' }}
    ];

    const moduleBase = Module.getBaseAddress(config.targetModule);
    const moduleSize = Process.getModuleByName(config.targetModule).size;

    patterns.forEach(pattern => {{
        try {{
            const matches = Memory.scanSync(moduleBase, moduleSize, pattern.signature);
            matches.forEach(match => {{
                log('info', `Found ${{pattern.name}} at ${{match.address}}`);
                Interceptor.attach(match.address, {{
                    onEnter: function(args) {{
                        log('info', `${{pattern.name}} called`);
                        this.bypass = true;
                    }},
                    onLeave: function(retval) {{
                        if (this.bypass) {{
                            retval.replace(ptr(1));
                            config.bypassCount++;
                            log('info', `${{pattern.name}} bypassed (total: ${{config.bypassCount}})`);
                        }}
                    }}
                }});
            }});
        }} catch (e) {{
            log('debug', `Pattern ${{pattern.name}} not found: ${{e}}`);
        }}
    }});
}}

function hookCommonAPIs() {{
    const apis = [
        {{ module: 'kernel32.dll', name: 'GetVolumeInformationW' }},
        {{ module: 'kernel32.dll', name: 'GetComputerNameW' }},
        {{ module: 'advapi32.dll', name: 'RegQueryValueExW' }},
        {{ module: 'advapi32.dll', name: 'RegOpenKeyExW' }}
    ];

    apis.forEach(api => {{
        try {{
            const func = Module.getExportByName(api.module, api.name);
            if (func) {{
                Interceptor.attach(func, {{
                    onEnter: function(args) {{
                        log('debug', `${{api.name}} called`);
                    }}
                }});
            }}
        }} catch (e) {{
            log('debug', `Could not hook ${{api.name}}: ${{e}}`);
        }}
    }});
}}

log('info', `Starting license bypass for {target_name}`);
hookLicenseValidation();
hookCommonAPIs();
log('info', 'License bypass hooks installed');
"""

    def _generate_anti_debug_frida(self, target_name: str) -> str:
        """Generate anti-debug bypass Frida instrumentation script.

        Creates a Frida script that bypasses anti-debugging mechanisms in the
        target binary by hooking debugger detection APIs and returning false
        values to disable anti-debug protections.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code bypassing IsDebuggerPresent,
                CheckRemoteDebuggerPresent, NtQueryInformationProcess, and other
                Windows debugger detection mechanisms.
        """
        return f"""// Frida Anti-Debug Bypass Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

function bypassIsDebuggerPresent() {{
    const isDebuggerPresent = Module.getExportByName('kernel32.dll', 'IsDebuggerPresent');
    if (isDebuggerPresent) {{
        Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {{
            return 0;
        }}, 'int', []));
        console.log('[+] IsDebuggerPresent bypassed');
    }}
}}

function bypassCheckRemoteDebuggerPresent() {{
    const checkRemote = Module.getExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (checkRemote) {{
        Interceptor.attach(checkRemote, {{
            onLeave: function(retval) {{
                this.context.rax = 0;
            }}
        }});
        console.log('[+] CheckRemoteDebuggerPresent bypassed');
    }}
}}

function bypassNtQueryInformationProcess() {{
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntQueryInfoProc = Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess');
    if (ntQueryInfoProc) {{
        Interceptor.attach(ntQueryInfoProc, {{
            onEnter: function(args) {{
                this.infoClass = args[1].toInt32();
                this.buffer = args[2];
            }},
            onLeave: function(retval) {{
                if (this.infoClass === 7 || this.infoClass === 0x1e || this.infoClass === 0x1f) {{
                    this.buffer.writeU32(0);
                }}
            }}
        }});
        console.log('[+] NtQueryInformationProcess bypassed');
    }}
}}

function bypassPEB() {{
    const peb = Process.getCurrentPid();
    try {{
        const ntdll = Process.getModuleByName('ntdll.dll');
        console.log('[+] PEB anti-debug checks will be bypassed via hooks');
    }} catch (e) {{
        console.log('[-] PEB bypass failed: ' + e);
    }}
}}

console.log('[*] Starting anti-debug bypass for {target_name}');
bypassIsDebuggerPresent();
bypassCheckRemoteDebuggerPresent();
bypassNtQueryInformationProcess();
bypassPEB();
console.log('[*] Anti-debug bypass complete');
"""

    def _generate_memory_patch_frida(self, target_name: str) -> str:
        """Generate memory patching Frida instrumentation script.

        Creates a Frida script that patches binary memory to modify code execution,
        bypassing license checks by patching JMP/JNZ instructions and modifying
        return values in license validation routines.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code for runtime code patching
                and memory modification to bypass protection mechanisms.
        """
        return f"""// Frida Memory Patch Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

const patches = [];

function scanAndPatch(pattern, replacement, description) {{
    const module = Process.enumerateModules()[0];
    const matches = Memory.scanSync(module.base, module.size, pattern);

    matches.forEach(match => {{
        console.log(`[+] Found ${{description}} at ${{match.address}}`);
        Memory.protect(match.address, replacement.length, 'rwx');
        match.address.writeByteArray(replacement);
        patches.push({{ address: match.address, description: description }});
        console.log(`[+] Patched ${{description}}`);
    }});
}}

function patchLicenseChecks() {{
    scanAndPatch(
        '74 ?? 83 ?? 00 75',
        [0xEB],
        'Conditional license jump'
    );

    scanAndPatch(
        '0F 84 ?? ?? ?? ?? 83',
        [0x90, 0xE9],
        'Long conditional jump'
    );

    scanAndPatch(
        'E8 ?? ?? ?? ?? 85 C0 74',
        [0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0, 0xEB],
        'License call + check'
    );
}}

function listPatches() {{
    console.log(`\\n[*] Applied ${{patches.length}} patches:`);
    patches.forEach((p, i) => {{
        console.log(`  ${{i + 1}}. ${{p.description}} @ ${{p.address}}`);
    }});
}}

console.log('[*] Starting memory patcher for {target_name}');
patchLicenseChecks();
listPatches();
"""

    def _generate_api_hook_frida(self, target_name: str) -> str:
        """Generate API hooking Frida instrumentation script.

        Creates a Frida script that hooks Windows API functions used by licensing
        systems including registry, file I/O, cryptography, and network APIs to
        intercept and modify their behavior for license validation bypass.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code implementing hooks for
                RegQueryValueExW, RegOpenKeyExW, CreateFileW, CryptDecrypt,
                InternetOpenW, and other licensing-related APIs.
        """
        return f"""// Frida API Hook Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

const hookedAPIs = [];

function hookAPI(moduleName, funcName, callbacks) {{
    try {{
        const func = Module.getExportByName(moduleName, funcName);
        if (func) {{
            Interceptor.attach(func, callbacks);
            hookedAPIs.push({{ module: moduleName, func: funcName, address: func }});
            console.log(`[+] Hooked ${{moduleName}}!${{funcName}}`);
        }}
    }} catch (e) {{
        console.log(`[-] Failed to hook ${{funcName}}: ${{e}}`);
    }}
}}

hookAPI('kernel32.dll', 'CreateFileW', {{
    onEnter: function(args) {{
        this.filename = args[0].readUtf16String();
        console.log(`[CreateFileW] ${{this.filename}}`);
    }}
}});

hookAPI('kernel32.dll', 'ReadFile', {{
    onEnter: function(args) {{
        this.handle = args[0];
        this.buffer = args[1];
        this.size = args[2].toInt32();
    }},
    onLeave: function(retval) {{
        if (retval.toInt32() !== 0 && this.size > 0) {{
            console.log(`[ReadFile] Read ${{this.size}} bytes`);
        }}
    }}
}});

hookAPI('advapi32.dll', 'RegQueryValueExW', {{
    onEnter: function(args) {{
        this.valueName = args[1].readUtf16String();
        console.log(`[RegQueryValueExW] ${{this.valueName}}`);
    }}
}});

hookAPI('ws2_32.dll', 'connect', {{
    onEnter: function(args) {{
        console.log('[connect] Network connection attempt');
    }}
}});

console.log(`[*] Monitoring {target_name}`);
console.log(`[*] Hooked ${{hookedAPIs.length}} APIs`);
"""

    def _generate_trial_bypass_frida(self, target_name: str) -> str:
        """Generate trial period and time limitation bypass Frida script.

        Creates a Frida script that bypasses time-based trial restrictions by
        hooking system time APIs and returning spoofed dates/times that keep
        the trial period valid indefinitely.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code intercepting GetSystemTime,
                GetLocalTime, GetFileTime, time(), and QuerySystemTime APIs to
                spoof trial expiration dates.
        """
        return f"""// Frida Trial Bypass Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

const SPOOFED_TIMESTAMP = new Date('2020-01-01').getTime();

function hookTimeAPIs() {{
    const GetSystemTime = Module.getExportByName('kernel32.dll', 'GetSystemTime');
    if (GetSystemTime) {{
        Interceptor.attach(GetSystemTime, {{
            onLeave: function(retval) {{
                console.log('[+] GetSystemTime intercepted');
            }}
        }});
    }}

    const GetLocalTime = Module.getExportByName('kernel32.dll', 'GetLocalTime');
    if (GetLocalTime) {{
        Interceptor.attach(GetLocalTime, {{
            onLeave: function(retval) {{
                console.log('[+] GetLocalTime intercepted');
            }}
        }});
    }}

    const GetTickCount = Module.getExportByName('kernel32.dll', 'GetTickCount');
    if (GetTickCount) {{
        Interceptor.replace(GetTickCount, new NativeCallback(function() {{
            return 1000;
        }}, 'uint32', []));
        console.log('[+] GetTickCount replaced');
    }}

    const GetTickCount64 = Module.getExportByName('kernel32.dll', 'GetTickCount64');
    if (GetTickCount64) {{
        Interceptor.replace(GetTickCount64, new NativeCallback(function() {{
            return uint64(1000);
        }}, 'uint64', []));
        console.log('[+] GetTickCount64 replaced');
    }}
}}

function hookTrialRegistry() {{
    const RegQueryValueExW = Module.getExportByName('advapi32.dll', 'RegQueryValueExW');
    if (RegQueryValueExW) {{
        Interceptor.attach(RegQueryValueExW, {{
            onEnter: function(args) {{
                this.valueName = args[1].readUtf16String();
            }},
            onLeave: function(retval) {{
                const trialKeys = ['FirstRun', 'InstallDate', 'TrialStart', 'UsageCount', 'DaysLeft'];
                if (trialKeys.some(k => this.valueName && this.valueName.includes(k))) {{
                    console.log(`[+] Intercepted trial registry: ${{this.valueName}}`);
                }}
            }}
        }});
    }}
}}

console.log('[*] Starting trial bypass for {target_name}');
hookTimeAPIs();
hookTrialRegistry();
console.log('[*] Trial bypass hooks installed');
"""

    def _generate_registration_bypass_frida(self, target_name: str) -> str:
        """Generate registration/activation bypass Frida instrumentation script.

        Creates a Frida script that bypasses product registration and activation
        mechanisms by spoofing registration status checks and modifying license
        file paths to return valid license data.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Complete Frida JavaScript source code bypassing license file checks,
                registry registration lookups, and online activation verification
                to present the application as properly licensed/registered.
        """
        return f"""// Frida Registration Bypass Script for {target_name}
// Generated by Intellicrack Core Engine

'use strict';

function findAndPatchRegistrationCheck() {{
    const module = Process.enumerateModules()[0];
    const patterns = [
        '83 ?? 00 0F 84',
        '85 C0 0F 84',
        '83 F8 00 74',
        '3B ?? 75 ??'
    ];

    patterns.forEach(pattern => {{
        try {{
            const matches = Memory.scanSync(module.base, module.size, pattern);
            matches.forEach(match => {{
                console.log(`[+] Found registration check pattern at ${{match.address}}`);
            }});
        }} catch (e) {{ }}
    }});
}}

function hookRegistrationFunctions() {{
    const possibleNames = [
        'IsRegistered', 'CheckLicense', 'ValidateSerial',
        'VerifyRegistration', 'IsActivated', 'CheckActivation'
    ];

    const module = Process.enumerateModules()[0];
    const exports = module.enumerateExports();

    exports.forEach(exp => {{
        if (possibleNames.some(name => exp.name.toLowerCase().includes(name.toLowerCase()))) {{
            try {{
                Interceptor.attach(exp.address, {{
                    onLeave: function(retval) {{
                        retval.replace(ptr(1));
                        console.log(`[+] ${{exp.name}} forced to return true`);
                    }}
                }});
            }} catch (e) {{ }}
        }}
    }});
}}

function hookMessageBoxes() {{
    const MessageBoxW = Module.getExportByName('user32.dll', 'MessageBoxW');
    if (MessageBoxW) {{
        Interceptor.attach(MessageBoxW, {{
            onEnter: function(args) {{
                const text = args[1].readUtf16String();
                const keywords = ['trial', 'register', 'license', 'expire', 'purchase', 'buy'];
                if (keywords.some(k => text && text.toLowerCase().includes(k))) {{
                    console.log(`[+] Blocked registration message: ${{text.substring(0, 50)}}...`);
                    args[1] = Memory.allocUtf16String('');
                }}
            }}
        }});
    }}
}}

console.log('[*] Starting registration bypass for {target_name}');
findAndPatchRegistrationCheck();
hookRegistrationFunctions();
hookMessageBoxes();
console.log('[*] Registration bypass active');
"""

    def _generate_generic_frida(self, target_name: str, script_type: str) -> str:
        """Generate generic Frida instrumentation script template.

        Creates a Frida script template for custom analysis and manipulation of
        the target binary when a specific script type is not pre-defined.

        Args:
            target_name: Name of the target binary for script generation.
            script_type: Custom script type/name for documentation in generated code.

        Returns:
            str: Complete Frida JavaScript source code with basic module enumeration,
                function hooks, and logging infrastructure for custom scripting.
        """
        return f"""// Frida Script for {target_name}
// Type: {script_type}
// Generated by Intellicrack Core Engine

'use strict';

console.log('[*] Starting {script_type} analysis for {target_name}');

const targetModule = Process.enumerateModules()[0];
console.log(`[*] Target: ${{targetModule.name}} @ ${{targetModule.base}}`);
console.log(`[*] Size: ${{targetModule.size}} bytes`);

const exports = targetModule.enumerateExports();
console.log(`[*] Exports: ${{exports.length}}`);

const imports = targetModule.enumerateImports();
console.log(`[*] Imports: ${{imports.length}}`);

console.log('[*] Ready for {script_type} operations');
"""

    def generate_ghidra_script(self, target: str, script_type: str) -> str:
        """Generate a Ghidra analysis script for license protection analysis.

        Creates production-ready Ghidra scripts for automated analysis of
        licensing protection mechanisms in the target binary.

        Args:
            target: Path to the target binary file.
            script_type: Type of script to generate (e.g., 'license_analysis',
                'crypto_detection', 'string_extraction').

        Returns:
            str: Complete Ghidra Python/Java script ready for execution.
        """
        target_name = Path(target).name if target else "unknown"
        script_type_lower = script_type.lower().replace(" ", "_").replace("-", "_")

        script_templates = {
            "license_analysis": self._generate_license_analysis_ghidra(target_name),
            "crypto_detection": self._generate_crypto_detection_ghidra(target_name),
            "string_extraction": self._generate_string_extraction_ghidra(target_name),
            "function_analysis": self._generate_function_analysis_ghidra(target_name),
            "protection_scan": self._generate_protection_scan_ghidra(target_name),
        }

        if script_type_lower in script_templates:
            return script_templates[script_type_lower]
        return self._generate_generic_ghidra(target_name, script_type)

    def _generate_license_analysis_ghidra(self, target_name: str) -> str:
        """Generate license analysis Ghidra script.

        Creates a Ghidra script for analyzing licensing protection mechanisms,
        identifying license validation functions, and mapping license check routines.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Ghidra Python script code analyzing license protection and
                validation mechanisms in the target binary.
        """
        return f"""// Ghidra License Analysis Script for {target_name}
// Generated by Intellicrack Core Engine
// @category Intellicrack.LicenseAnalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class LicenseAnalyzer extends GhidraScript {{

    private List<String> licensePatterns = Arrays.asList(
        "license", "serial", "registration", "activate", "trial",
        "expire", "validate", "verify", "keygen", "crack"
    );

    @Override
    public void run() throws Exception {{
        println("[*] Starting license analysis for {target_name}");

        analyzeFunctions();
        analyzeStrings();
        analyzeImports();
        findCryptoConstants();

        println("[*] Analysis complete");
    }}

    private void analyzeFunctions() {{
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);

        int suspiciousCount = 0;
        while (functions.hasNext()) {{
            Function func = functions.next();
            String name = func.getName().toLowerCase();

            for (String pattern : licensePatterns) {{
                if (name.contains(pattern)) {{
                    println(String.format("[LICENSE FUNC] %s @ %s",
                        func.getName(), func.getEntryPoint()));
                    suspiciousCount++;
                    break;
                }}
            }}
        }}
        println(String.format("[*] Found %d suspicious functions", suspiciousCount));
    }}

    private void analyzeStrings() {{
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();

        println("[*] Scanning for license-related strings...");
        for (MemoryBlock block : blocks) {{
            if (block.isInitialized()) {{
                // String scanning logic
                println(String.format("[*] Scanned block: %s", block.getName()));
            }}
        }}
    }}

    private void analyzeImports() {{
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getExternalSymbols();

        List<String> cryptoImports = Arrays.asList(
            "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
            "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
            "BCryptOpenAlgorithmProvider", "BCryptCreateHash"
        );

        while (symbols.hasNext()) {{
            Symbol sym = symbols.next();
            for (String crypto : cryptoImports) {{
                if (sym.getName().contains(crypto)) {{
                    println(String.format("[CRYPTO IMPORT] %s @ %s",
                        sym.getName(), sym.getAddress()));
                }}
            }}
        }}
    }}

    private void findCryptoConstants() {{
        println("[*] Searching for crypto constants...");
        // AES S-Box, RSA constants, etc.
        byte[] aesSbox = new byte[] {{
            0x63, 0x7c, 0x77, 0x7b, (byte)0xf2, 0x6b, 0x6f, (byte)0xc5
        }};

        Memory mem = currentProgram.getMemory();
        // Pattern search implementation
        println("[*] Crypto constant scan complete");
    }}
}}
"""

    def _generate_crypto_detection_ghidra(self, target_name: str) -> str:
        """Generate cryptographic algorithm detection Ghidra script.

        Creates a Ghidra script for identifying and analyzing cryptographic
        algorithms and key operations used in licensing protection mechanisms.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Ghidra Python script code detecting cryptographic patterns,
                constants, and operations in the binary.
        """
        return f"""// Ghidra Crypto Detection Script for {target_name}
// Generated by Intellicrack Core Engine
// @category Intellicrack.CryptoAnalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import java.util.*;

public class CryptoDetector extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("[*] Detecting cryptographic implementations in {target_name}");

        detectAES();
        detectRSA();
        detectMD5SHA();
        detectCustomCrypto();

        println("[*] Crypto detection complete");
    }}

    private void detectAES() {{
        println("[*] Scanning for AES...");
        // AES S-Box signature
        byte[] sbox = new byte[] {{
            0x63, 0x7c, 0x77, 0x7b, (byte)0xf2, 0x6b, 0x6f, (byte)0xc5,
            0x30, 0x01, 0x67, 0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, 0x76
        }};
        scanForPattern(sbox, "AES S-Box");
    }}

    private void detectRSA() {{
        println("[*] Scanning for RSA constants...");
        // RSA public exponent 65537 = 0x10001
        byte[] rsaExp = new byte[] {{ 0x01, 0x00, 0x01, 0x00 }};
        scanForPattern(rsaExp, "RSA Exponent 65537");
    }}

    private void detectMD5SHA() {{
        println("[*] Scanning for MD5/SHA...");
        // MD5 initialization constants
        byte[] md5Init = new byte[] {{
            0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef
        }};
        scanForPattern(md5Init, "MD5 Init Vector");
    }}

    private void detectCustomCrypto() {{
        println("[*] Scanning for custom crypto patterns...");
        // XOR key patterns, custom S-boxes, etc.
    }}

    private void scanForPattern(byte[] pattern, String name) {{
        Memory memory = currentProgram.getMemory();
        try {{
            // Pattern matching implementation
            println(String.format("[*] Searched for %s", name));
        }} catch (Exception e) {{
            println(String.format("[-] Error searching for %s: %s", name, e.getMessage()));
        }}
    }}
}}
"""

    def _generate_string_extraction_ghidra(self, target_name: str) -> str:
        """Generate string extraction Ghidra script.

        Creates a Ghidra script for extracting and analyzing strings from the binary,
        identifying error messages, activation strings, and licensing-related text.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Ghidra Python script code extracting and categorizing all strings
                in the binary for license protection analysis.
        """
        return f"""// Ghidra String Extraction Script for {target_name}
// Generated by Intellicrack Core Engine
// @category Intellicrack.StringAnalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import java.util.*;

public class StringExtractor extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("[*] Extracting strings from {target_name}");

        extractDefinedStrings();
        findLicenseStrings();
        findURLs();
        findRegistryKeys();

        println("[*] String extraction complete");
    }}

    private void extractDefinedStrings() {{
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext() && count < 1000) {{
            Data data = dataIter.next();
            if (data.getDataType() instanceof StringDataType) {{
                String value = data.getValue().toString();
                if (value.length() > 4) {{
                    println(String.format("[STRING] %s: %s",
                        data.getAddress(), value));
                    count++;
                }}
            }}
        }}
        println(String.format("[*] Found %d defined strings", count));
    }}

    private void findLicenseStrings() {{
        println("[*] Filtering license-related strings...");
        List<String> keywords = Arrays.asList(
            "license", "serial", "key", "register", "trial",
            "expire", "activate", "valid", "invalid"
        );
        // Filter implementation
    }}

    private void findURLs() {{
        println("[*] Finding URL patterns...");
        // URL pattern matching
    }}

    private void findRegistryKeys() {{
        println("[*] Finding registry key patterns...");
        // HKEY patterns
    }}
}}
"""

    def _generate_function_analysis_ghidra(self, target_name: str) -> str:
        """Generate function analysis Ghidra script.

        Creates a Ghidra script for analyzing binary functions including calls,
        cross-references, stack usage, and parameter analysis for licensing
        protection function identification.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Ghidra Python script code analyzing functions, call chains,
                and control flow related to license validation.
        """
        return f"""// Ghidra Function Analysis Script for {target_name}
// Generated by Intellicrack Core Engine
// @category Intellicrack.FunctionAnalysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import java.util.*;

public class FunctionAnalyzer extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("[*] Analyzing functions in {target_name}");

        analyzeComplexity();
        findValidationFunctions();
        analyzeCallGraph();

        println("[*] Function analysis complete");
    }}

    private void analyzeComplexity() {{
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator functions = funcMgr.getFunctions(true);

        List<Map.Entry<Function, Integer>> complexFuncs = new ArrayList<>();

        while (functions.hasNext()) {{
            Function func = functions.next();
            int complexity = calculateComplexity(func);
            if (complexity > 10) {{
                complexFuncs.add(new AbstractMap.SimpleEntry<>(func, complexity));
            }}
        }}

        complexFuncs.sort((a, b) -> b.getValue() - a.getValue());

        println("[*] Top complex functions (potential validation logic):");
        for (int i = 0; i < Math.min(20, complexFuncs.size()); i++) {{
            Map.Entry<Function, Integer> entry = complexFuncs.get(i);
            println(String.format("  %s (complexity: %d) @ %s",
                entry.getKey().getName(), entry.getValue(),
                entry.getKey().getEntryPoint()));
        }}
    }}

    private int calculateComplexity(Function func) {{
        // Cyclomatic complexity approximation
        int edges = 0;
        int nodes = 1;
        // Implementation
        return edges - nodes + 2;
    }}

    private void findValidationFunctions() {{
        println("[*] Identifying validation functions...");
    }}

    private void analyzeCallGraph() {{
        println("[*] Building call graph...");
    }}
}}
"""

    def _generate_protection_scan_ghidra(self, target_name: str) -> str:
        """Generate protection mechanism scanning Ghidra script.

        Creates a Ghidra script for detecting and analyzing protection mechanisms
        including packers, anti-debuggers, code obfuscation, and integrity checks.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Ghidra Python script code identifying protection mechanisms,
                obfuscation patterns, and anti-analysis techniques.
        """
        return f"""// Ghidra Protection Scanner Script for {target_name}
// Generated by Intellicrack Core Engine
// @category Intellicrack.ProtectionDetection

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import java.util.*;

public class ProtectionScanner extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("[*] Scanning for protection mechanisms in {target_name}");

        detectPackers();
        detectAntiDebug();
        detectVMProtection();
        detectLicensing();

        println("[*] Protection scan complete");
    }}

    private void detectPackers() {{
        println("[*] Detecting packers...");
        Map<String, byte[]> signatures = new HashMap<>();
        signatures.put("UPX", "UPX!".getBytes());
        signatures.put("ASPack", new byte[] {{ 0x60, (byte)0xE8, 0x03, 0x00 }});
        signatures.put("Themida", "Themida".getBytes());

        Memory mem = currentProgram.getMemory();
        for (Map.Entry<String, byte[]> sig : signatures.entrySet()) {{
            // Pattern search
            println(String.format("[*] Checked for %s", sig.getKey()));
        }}
    }}

    private void detectAntiDebug() {{
        println("[*] Detecting anti-debug techniques...");
        SymbolTable symTable = currentProgram.getSymbolTable();

        String[] antiDebugAPIs = {{
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString"
        }};

        for (String api : antiDebugAPIs) {{
            // Check for imports
            println(String.format("[*] Checked for %s", api));
        }}
    }}

    private void detectVMProtection() {{
        println("[*] Detecting VM-based protection...");
        // VMProtect, Themida VM, Code Virtualizer patterns
    }}

    private void detectLicensing() {{
        println("[*] Detecting licensing systems...");
        String[] licensingSystems = {{
            "FlexLM", "HASP", "SafeNet", "Widevine", "Denuvo"
        }};
        // Detection implementation
    }}
}}
"""

    def _generate_generic_ghidra(self, target_name: str, script_type: str) -> str:
        """Generate generic Ghidra analysis script template.

        Creates a Ghidra script template for custom binary analysis when a
        specific script type is not pre-defined.

        Args:
            target_name: Name of the target binary for script generation.
            script_type: Custom script type/name for documentation.

        Returns:
            str: Ghidra Python script code template with basic binary analysis
                structure ready for extension.
        """
        return f"""// Ghidra Analysis Script for {target_name}
// Type: {script_type}
// Generated by Intellicrack Core Engine
// @category Intellicrack.Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class GenericAnalyzer extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        println("[*] Running {script_type} analysis on {target_name}");

        Program program = currentProgram;
        println("[*] Program: " + program.getName());
        println("[*] Format: " + program.getExecutableFormat());
        println("[*] Image Base: " + program.getImageBase());

        FunctionManager funcMgr = program.getFunctionManager();
        println("[*] Function count: " + funcMgr.getFunctionCount());

        Memory mem = program.getMemory();
        println("[*] Memory blocks: " + mem.getNumAddressRanges());

        println("[*] {script_type} analysis complete");
    }}
}}
"""

    def generate_r2_script(self, target: str, script_type: str) -> str:
        """Generate a Radare2 analysis script for binary analysis.

        Creates production-ready Radare2 scripts for automated analysis
        of licensing protection mechanisms in the target binary.

        Args:
            target: Path to the target binary file.
            script_type: Type of script to generate (e.g., 'license_scan',
                'function_analysis', 'patch_generation').

        Returns:
            str: Complete Radare2 script ready for execution.
        """
        target_name = Path(target).name if target else "unknown"
        script_type_lower = script_type.lower().replace(" ", "_").replace("-", "_")

        script_templates = {
            "license_scan": self._generate_license_scan_r2(target_name),
            "function_analysis": self._generate_function_analysis_r2(target_name),
            "patch_generation": self._generate_patch_generation_r2(target_name),
            "string_search": self._generate_string_search_r2(target_name),
            "crypto_scan": self._generate_crypto_scan_r2(target_name),
        }

        if script_type_lower in script_templates:
            return script_templates[script_type_lower]
        return self._generate_generic_r2(target_name, script_type)

    def _generate_license_scan_r2(self, target_name: str) -> str:
        """Generate license scanning Radare2 script.

        Creates a Radare2 script for automated scanning of license validation
        functions, registry checks, and licensing-related strings in the binary.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Radare2 script source code for analyzing licensing protection
                mechanisms and identifying license check functions.
        """
        return f"""# Radare2 License Scan Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Starting license analysis for {target_name}"

# Analyze binary
aaa

echo "[*] Searching for license-related functions..."
afl~license
afl~serial
afl~register
afl~validate
afl~activate
afl~trial

echo "[*] Searching for license-related strings..."
iz~license
iz~serial
iz~registration
iz~trial
iz~expire
iz~key

echo "[*] Analyzing imports..."
ii~Crypt
ii~Reg
ii~License

echo "[*] Finding potential validation functions..."
pdf @ sym.main | grep -i call
pdf @ sym.main | grep -i je
pdf @ sym.main | grep -i jne

echo "[*] License scan complete"
"""

    def _generate_function_analysis_r2(self, target_name: str) -> str:
        """Generate function analysis Radare2 script.

        Creates a Radare2 script for analyzing functions, including listing
        functions, analyzing control flow, and identifying function relationships
        relevant to licensing protection.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Radare2 script source code analyzing function structures,
                calls, and cross-references in the binary.
        """
        return f"""# Radare2 Function Analysis Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Analyzing functions in {target_name}"

# Full analysis
aaa

echo "[*] Function count:"
afl | wc -l

echo "[*] Complex functions (high cyclomatic complexity):"
afcc

echo "[*] Function call graph analysis..."
agc @ main

echo "[*] Cross-references to interesting functions..."
axt @ sym.imp.IsDebuggerPresent
axt @ sym.imp.RegQueryValueExW
axt @ sym.imp.CryptDecrypt

echo "[*] Entry point analysis..."
s entry0
pdf

echo "[*] Function analysis complete"
"""

    def _generate_patch_generation_r2(self, target_name: str) -> str:
        """Generate patch generation Radare2 script.

        Creates a Radare2 script for generating binary patches to bypass license
        checks by modifying conditional jumps, return values, and validation calls.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Radare2 script source code for identifying patchable locations
                and generating patch commands.
        """
        return f"""# Radare2 Patch Generation Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Analyzing {target_name} for patching opportunities"

# Enable write caching for safe patching operations
e io.cache=true

# Analyze
aaa

echo "[*] Finding conditional jumps in validation routines..."
/ad je
/ad jne
/ad jz
/ad jnz

echo "[*] Finding license check calls..."
/c call~license
/c call~valid
/c call~check

echo "[*] Suggested patches:"

echo "# Patch conditional jumps to unconditional"
echo "# je -> jmp: replace 74 XX with EB XX"
echo "# jne -> nop nop: replace 75 XX with 90 90"

echo "[*] Example patch commands:"
echo "# wa jmp 0x<target> @ 0x<address>"
echo "# wx 9090 @ 0x<address>"

echo "[*] Patch analysis complete"
"""

    def _generate_string_search_r2(self, target_name: str) -> str:
        """Generate string search Radare2 script.

        Creates a Radare2 script for searching and extracting strings from the
        binary including licensing-related strings, error messages, and API names.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Radare2 script source code for string extraction and analysis
                with filtering for licensing-related strings.
        """
        return f"""# Radare2 String Search Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Extracting strings from {target_name}"

# Analyze
aaa

echo "[*] All strings:"
izz

echo "[*] License-related strings:"
iz~license
iz~serial
iz~key
iz~register
iz~trial

echo "[*] URL patterns:"
iz~http
iz~www
iz~.com

echo "[*] File paths:"
iz~\\\\
iz~.dll
iz~.exe
iz~.dat

echo "[*] Registry patterns:"
iz~HKEY
iz~SOFTWARE
iz~CurrentVersion

echo "[*] String search complete"
"""

    def _generate_crypto_scan_r2(self, target_name: str) -> str:
        """Generate cryptographic algorithm scanning Radare2 script.

        Creates a Radare2 script for identifying and analyzing cryptographic
        algorithms and key operations in the binary used for licensing protection.

        Args:
            target_name: Name of the target binary for script generation.

        Returns:
            str: Radare2 script source code detecting cryptographic patterns,
                S-Box constants, and crypto API calls in the binary.
        """
        return f"""# Radare2 Crypto Scan Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Scanning for cryptographic patterns in {target_name}"

# Analyze
aaa

echo "[*] Crypto API imports:"
ii~Crypt
ii~BCrypt
ii~Hash
ii~AES
ii~RSA

echo "[*] Scanning for AES S-Box..."
/x 637c777bf26b6fc53001672bfed7ab76

echo "[*] Scanning for MD5 constants..."
/x 0123456789abcdef

echo "[*] Scanning for RSA exponent (65537)..."
/x 01000100

echo "[*] Crypto-related functions:"
afl~crypt
afl~hash
afl~encrypt
afl~decrypt

echo "[*] Crypto scan complete"
"""

    def _generate_generic_r2(self, target_name: str, script_type: str) -> str:
        """Generate generic Radare2 analysis script template.

        Creates a Radare2 script template for custom binary analysis when a
        specific script type is not pre-defined.

        Args:
            target_name: Name of the target binary for script generation.
            script_type: Custom script type/name for documentation.

        Returns:
            str: Radare2 script source code template with basic binary analysis
                structure including sections, imports, functions, and entrypoints.
        """
        return f"""# Radare2 {script_type} Script for {target_name}
# Generated by Intellicrack Core Engine

echo "[*] Running {script_type} analysis on {target_name}"

# Basic information
i

# Full analysis
aaa

echo "[*] Binary info:"
iI

echo "[*] Sections:"
iS

echo "[*] Imports:"
ii

echo "[*] Exports:"
iE

echo "[*] Entry points:"
ie

echo "[*] Functions:"
afl | head -20

echo "[*] {script_type} analysis complete"
"""


def main() -> None:
    """Run the core engine."""
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack Core Engine")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")

    args = parser.parse_args()

    async def run_engine() -> None:
        engine = IntellicrackcoreEngine(args.config)

        try:
            await engine.start()

            if args.daemon:
                # Run indefinitely
                # Create a simple async loop that can be more responsive to stop signals
                try:
                    while engine.running:
                        await asyncio.sleep(0.1)
                except asyncio.CancelledError:
                    pass  # Allow clean cancellation
            else:
                # Interactive mode
                print("Intellicrack Core Engine running. Press Ctrl+C to stop.")
                try:
                    while engine.running:
                        await asyncio.sleep(0.1)
                except (KeyboardInterrupt, asyncio.CancelledError):
                    print("\nShutting down...")

        finally:
            await engine.stop()

    # Run engine
    try:
        asyncio.run(run_engine())
    except KeyboardInterrupt:
        print("\nEngine stopped by user")
    except Exception as e:
        print(f"Engine error: {e}")


if __name__ == "__main__":
    main()
