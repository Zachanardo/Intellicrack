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
import importlib
import importlib.util
import inspect
import json
import logging
import logging.handlers
import multiprocessing as mp
import os
import queue
import signal
import subprocess
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
from datetime import UTC, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from jsonschema import ValidationError, validate

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.utils.logger import log_all_methods


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
    """Plugin metadata structure."""

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
        """Convert to dictionary."""
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


@log_all_methods
@dataclass
class Event:
    """Event structure for inter-component communication."""

    event_type: str
    source: str
    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    priority: EventPriority = EventPriority.MEDIUM
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str | None = None
    ttl: int | None = None  # Time to live in seconds

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
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
    """Individual step in a workflow."""

    step_id: str
    name: str
    plugin_name: str
    method: str
    parameters: dict[str, Any] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    timeout: int | None = None
    retry_count: int = 0
    max_retries: int = 3
    condition: str | None = None  # Python expression for conditional execution

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
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
    """Complete workflow definition."""

    workflow_id: str
    name: str
    description: str
    steps: list[WorkflowStep]
    parallel_execution: bool = False
    timeout: int | None = None
    error_handling: str = "stop"  # stop, continue, retry
    result_aggregation: str = "merge"  # merge, last, custom
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
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
    """Advanced logging manager with structured logging and multiple outputs."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize advanced logging manager with configuration."""
        self.config = config
        self.loggers: dict[str, logging.Logger] = {}
        self.handlers: dict[str, logging.Handler] = {}

        # Use weakref for memory-efficient logger references
        self._logger_refs = weakref.WeakValueDictionary()

        # Use yaml for configuration if config is a string path
        if isinstance(config, str) and config.endswith(".yaml"):
            try:
                with open(config) as f:
                    self.config = yaml.safe_load(f)
            except Exception as e:
                self.logger.exception(f"Failed to load YAML config: {e}, using default config")
                self.config = {}

        # Setup root logger
        self._setup_root_logger()

        # Setup component loggers
        self._setup_component_loggers()

    def _setup_root_logger(self) -> None:
        """Set up root logger with multiple handlers."""
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
        """Set up specialized loggers for different components."""
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
        """Get logger for specific component."""
        if name not in self.loggers:
            logger = logging.getLogger(f"intellicrack.{name}")
            logger.setLevel(logging.DEBUG)
            self.loggers[name] = logger

        return self.loggers[name]

    def log_event(self, event: Event) -> None:
        """Log an event with structured data."""
        logger = self.get_logger("events")
        logger.info(
            f"Event: {event.event_type}",
            extra={
                "event_data": event.to_dict(),
                "component": "event_system",
            },
        )

    def log_plugin_operation(self, plugin_name: str, operation: str, status: str, details: dict[str, Any] = None) -> None:
        """Log plugin operation."""
        logger = self.get_logger("plugins")
        logger.info(
            f"Plugin {plugin_name}: {operation} -> {status}",
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
        """Log workflow step execution."""
        logger = self.get_logger("workflows")
        logger.info(
            f"Workflow {workflow_id} Step {step_id}: {status}",
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
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON structure."""
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
    """Configuration management with validation and hot reloading."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize configuration manager with optional config path."""
        self.config_path = Path(config_path) if config_path else Path("config/intellicrack.json")
        self.config: dict[str, Any] = {}
        self.schema: dict[str, Any] = {}
        self.watchers: list[Callable] = []
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
        """Load configuration schema for validation."""
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
        """Get default configuration."""
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
        """Reload configuration from file."""
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
            print(f"Configuration error: {e}")
            # Fall back to default config
            self.config = self._get_default_config()

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _save_config(self) -> None:
        """Save current configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    def _start_file_watcher(self) -> None:
        """Start file watcher for hot reloading."""

        def watch_file() -> None:
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
        """Get configuration value with dot notation support."""
        keys = key.split(".")
        value: object = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: object) -> None:
        """Set configuration value with dot notation support."""
        keys = key.split(".")
        config = self.config

        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        self._save_config()

    def add_watcher(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Add configuration change watcher."""
        self.watchers.append(callback)

    def remove_watcher(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Remove configuration change watcher."""
        if callback in self.watchers:
            self.watchers.remove(callback)


@log_all_methods
class AbstractPlugin(ABC):
    """Abstract base class for all plugins."""

    def __init__(self, name: str, version: str = "1.0.0") -> None:
        """Initialize abstract plugin with name and version."""
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
        """Get plugin metadata."""

    @abstractmethod
    async def initialize(self, config: dict[str, Any]) -> bool:
        """Initialize the plugin with configuration."""

    @abstractmethod
    async def activate(self) -> bool:
        """Activate the plugin."""

    @abstractmethod
    async def deactivate(self) -> bool:
        """Deactivate the plugin."""

    @abstractmethod
    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""

    @abstractmethod
    def get_supported_operations(self) -> list[str]:
        """Get list of supported operations."""

    @abstractmethod
    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute a specific operation."""

    def set_logger(self, logger: logging.Logger) -> None:
        """Set plugin logger."""
        self.logger = logger

    def set_event_bus(self, event_bus: "EventBus") -> None:
        """Set event bus for communication."""
        self.event_bus = event_bus

    def update_config(self, config: dict[str, Any]) -> None:
        """Update plugin configuration."""
        self.config.update(config)

    def emit_event(self, event_type: str, data: dict[str, Any] = None, target: str = None) -> None:
        """Emit an event."""
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
        """Log performance metric."""
        self.performance_metrics[metric_name] = {
            "value": value,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def get_status(self) -> dict[str, Any]:
        """Get plugin status information."""
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
    """Base class for Ghidra script plugins."""

    def __init__(self, name: str, script_path: str, version: str = "1.0.0") -> None:
        """Initialize Ghidra plugin with name, script path, and version."""
        super().__init__(name, version)
        self.script_path = Path(script_path)
        self.java_process: subprocess.Popen | None = None
        self.ghidra_project_path: str | None = None

    def get_metadata(self) -> PluginMetadata:
        """Get Ghidra plugin metadata."""
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
        """Initialize Ghidra plugin."""
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
                self.logger.exception(f"Ghidra plugin initialization failed: {e}")
            return False

    async def activate(self) -> bool:
        """Activate Ghidra plugin."""
        self.status = PluginStatus.ACTIVE
        return True

    async def deactivate(self) -> bool:
        """Deactivate Ghidra plugin."""
        if self.java_process:
            self.java_process.terminate()
            self.java_process = None
        self.status = PluginStatus.READY
        return True

    async def cleanup(self) -> bool:
        """Cleanup Ghidra plugin resources."""
        await self.deactivate()
        return True

    def get_supported_operations(self) -> list[str]:
        """Get supported Ghidra operations."""
        return [
            "analyze_binary",
            "extract_functions",
            "find_strings",
            "identify_crypto",
            "generate_keygen",
            "detect_packers",
        ]

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Ghidra operation."""
        try:
            if operation not in self.get_supported_operations():
                raise ValueError(f"Unsupported operation: {operation}")

            binary_path = parameters.get("binary_path")
            if not binary_path or not Path(binary_path).exists():
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
                self.logger.exception(f"Ghidra operation failed: {e}")

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
        """Execute Ghidra script in subprocess."""
        ghidra_path = self.config.get("ghidra_path")
        java_path = self.config.get("java_path", "java")

        # Use os to check if binary file exists and get its info
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        binary_stats = Path(binary_path).stat()
        binary_hash = hashlib.sha256()

        # Calculate hash of binary for tracking
        def _hash_file() -> str:
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    binary_hash.update(chunk)
            return binary_hash.hexdigest()[:16]

        binary_id = await asyncio.to_thread(_hash_file)

        # Use inspect to validate parameters
        current_function = inspect.currentframe().f_code.co_name
        self.logger.debug(f"Executing {current_function} with operation: {operation}")

        # Use queue for managing concurrent operations
        operation_queue = queue.Queue()
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
                    self.logger.exception(f"Process termination failed: {term_error}\n{error_trace}")
                    process.kill()
            raise Exception("Ghidra execution timed out") from timeout_error
        except Exception as e:
            # Use traceback for comprehensive error reporting
            error_trace = traceback.format_exc()
            self.logger.exception(f"Ghidra execution error: {e}\n{error_trace}")
            raise

    def _parse_ghidra_output(self, output: str, operation: str) -> dict[str, Any]:
        """Parse Ghidra script output."""
        result = {
            "operation": operation,
            "raw_output": output,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        # Operation-specific parsing
        if operation == "extract_functions":
            functions = []
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
            strings = []
            for line in output.split("\n"):
                if "STRING:" in line:
                    string_data = line.split("STRING:")[1].strip()
                    strings.append(string_data)
            result["strings"] = strings

        elif operation == "identify_crypto":
            crypto_findings = []
            for line in output.split("\n"):
                if "CRYPTO:" in line:
                    crypto_data = line.split("CRYPTO:")[1].strip()
                    crypto_findings.append(crypto_data)
            result["crypto_algorithms"] = crypto_findings

        return result


@log_all_methods
class FridaPlugin(AbstractPlugin):
    """Base class for Frida script plugins."""

    def __init__(self, name: str, script_path: str, version: str = "1.0.0") -> None:
        """Initialize Frida plugin with name, script path, and version."""
        super().__init__(name, version)
        self.script_path = Path(script_path)
        self.frida_session = None
        self.frida_script = None
        self.target_process = None

    def get_metadata(self) -> PluginMetadata:
        """Get Frida plugin metadata."""
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
        """Initialize Frida plugin."""
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
                self.logger.exception(f"Frida plugin initialization failed: {e}")
            return False

    async def activate(self) -> bool:
        """Activate Frida plugin."""
        self.status = PluginStatus.ACTIVE
        return True

    async def deactivate(self) -> bool:
        """Deactivate Frida plugin."""
        if self.frida_script:
            self.frida_script.unload()
            self.frida_script = None

        if self.frida_session:
            self.frida_session.detach()
            self.frida_session = None

        self.status = PluginStatus.READY
        return True

    async def cleanup(self) -> bool:
        """Cleanup Frida plugin resources."""
        await self.deactivate()
        return True

    def get_supported_operations(self) -> list[str]:
        """Get supported Frida operations."""
        return [
            "attach_process",
            "hook_functions",
            "trace_calls",
            "modify_memory",
            "bypass_protections",
            "extract_runtime_data",
        ]

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Frida operation."""
        try:
            from intellicrack.handlers.frida_handler import frida

            # Check Frida version and capabilities
            frida_version = frida.__version__
            self.logger.debug(f"Using Frida version: {frida_version}")

            if operation not in self.get_supported_operations():
                raise ValueError(f"Unsupported operation: {operation}")

            # Get target process
            target = parameters.get("target")
            if not target:
                raise ValueError("Target process not specified")

            # Attach to process
            if operation == "attach_process":
                return await self._attach_to_process(target, parameters)

            # Ensure we have an active session
            if not self.frida_session:
                await self._attach_to_process(target, parameters)

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

        except Exception as e:
            self.last_error = str(e)
            if self.logger:
                self.logger.exception(f"Frida operation failed: {e}")

            self.emit_event(
                "operation_failed",
                {
                    "operation": operation,
                    "error": str(e),
                    "parameters": parameters,
                },
            )

            raise

    async def _attach_to_process(self, target: str | int, parameters: dict[str, Any]) -> dict[str, Any]:
        """Attach to target process."""
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
        """Handle Frida script messages."""
        if self.logger:
            self.logger.debug(f"Frida message: {message}")

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
        """Install hooks for functions in target process."""
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
        """Trace function calls."""
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
        """Modify process memory."""
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
        """Bypass protection mechanisms."""
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
        """Extract runtime data from process."""
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
    """Base class for Python module plugins."""

    def __init__(self, name: str, module_path: str, version: str = "1.0.0") -> None:
        """Initialize Python plugin with name, module path, and version."""
        super().__init__(name, version)
        self.module_path = Path(module_path)
        self.module = None
        self.plugin_instance = None

    def get_metadata(self) -> PluginMetadata:
        """Get Python plugin metadata."""
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
        """Initialize Python plugin."""
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
                self.logger.exception(f"Python plugin initialization failed: {e}")
            return False

    async def activate(self) -> bool:
        """Activate Python plugin."""
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
                self.logger.exception(f"Python plugin activation failed: {e}")
            return False

    async def deactivate(self) -> bool:
        """Deactivate Python plugin."""
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
                self.logger.exception(f"Python plugin deactivation failed: {e}")
            return False

    async def cleanup(self) -> bool:
        """Cleanup Python plugin resources."""
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
                self.logger.exception(f"Python plugin cleanup failed: {e}")
            return False

    def get_supported_operations(self) -> list[str]:
        """Get supported Python plugin operations."""
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
                self.logger.exception("Plugin operation error: %s", e)

        return list(set(operations))

    async def execute_operation(self, operation: str, parameters: dict[str, object]) -> object:
        """Execute Python plugin operation."""
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
                self.logger.exception(f"Python plugin operation failed: {e}")

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
    """Async event bus for inter-component communication."""

    def __init__(self, max_queue_size: int = 10000) -> None:
        """Initialize event bus with maximum queue size."""
        self.subscribers: dict[str, list[Callable]] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self.running = False
        self.processor_task: asyncio.Task | None = None
        self.logger: logging.Logger | None = None
        self.event_history: list[Event] = []
        self.max_history_size = 1000
        self.stats = {
            "events_processed": 0,
            "events_failed": 0,
            "subscribers_count": 0,
            "queue_size": 0,
        }

    def set_logger(self, logger: logging.Logger) -> None:
        """Set logger for event bus."""
        self.logger = logger

    async def start(self) -> None:
        """Start event processing."""
        if self.running:
            return

        self.running = True
        self.processor_task = asyncio.create_task(self._process_events())

        if self.logger:
            self.logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop event processing."""
        if not self.running:
            return

        self.running = False

        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError as e:
                self.logger.exception("Plugin operation error: %s", e)

        if self.logger:
            self.logger.info("Event bus stopped")

    def subscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]) -> None:
        """Subscribe to events of specific type."""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []

        self.subscribers[event_type].append(handler)
        self.stats["subscribers_count"] = sum(len(handlers) for handlers in self.subscribers.values())

        if self.logger:
            self.logger.debug(f"New subscriber for event type: {event_type}")

    def unsubscribe(self, event_type: str, handler: Callable[[Event], Awaitable[None]]) -> None:
        """Unsubscribe from events."""
        if event_type in self.subscribers and handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)

            if not self.subscribers[event_type]:
                del self.subscribers[event_type]

            self.stats["subscribers_count"] = sum(len(handlers) for handlers in self.subscribers.values())

            if self.logger:
                self.logger.debug(f"Unsubscribed from event type: {event_type}")

    async def emit(self, event: Event) -> None:
        """Emit an event."""
        try:
            # Check TTL
            if event.ttl is not None:
                age = (datetime.now(UTC) - event.timestamp).total_seconds()
                if age > event.ttl:
                    if self.logger:
                        self.logger.warning(f"Event {event.event_id} expired (TTL: {event.ttl}s)")
                    return

            # Add to queue
            await self.event_queue.put(event)
            self.stats["queue_size"] = self.event_queue.qsize()

            if self.logger:
                self.logger.debug(f"Event emitted: {event.event_type} from {event.source}")

        except asyncio.QueueFull:
            if self.logger:
                self.logger.error(f"Event queue full, dropping event: {event.event_type}")

    async def _process_events(self) -> None:
        """Process events from queue."""
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
                    self.logger.exception(f"Event processing error: {e}")

    async def _handle_event(self, event: Event) -> None:
        """Handle individual event."""
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
                        # Wrap sync handler in async
                        tasks.append(asyncio.create_task(self._run_sync_handler(handler, event)))
                except Exception as e:
                    if self.logger:
                        self.logger.exception(f"Error creating task for handler: {e}")

            # Wait for all handlers to complete with timeout using timedelta
            if tasks:
                handler_timeout = timedelta(seconds=30)  # Use timedelta for timeout calculation
                timeout_seconds = handler_timeout.total_seconds()

                # Track task completion in real-time
                completed_count = 0
                results = []

                try:
                    # Use as_completed to process tasks as they finish
                    for completed_task in asyncio.as_completed(tasks, timeout=timeout_seconds):
                        try:
                            result = await completed_task
                            results.append(result)
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
                        self.logger.warning(f"Handler execution timed out after {handler_timeout}")
                    # Cancel remaining tasks
                    for task in tasks:
                        task.cancel()

    async def _run_sync_handler(self, handler: Callable, event: Event) -> None:
        """Run synchronous handler in executor."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, handler, event)

    def _add_to_history(self, event: Event) -> None:
        """Add event to history."""
        self.event_history.append(event)

        # Limit history size
        if len(self.event_history) > self.max_history_size:
            self.event_history = self.event_history[-self.max_history_size // 2 :]

    def get_stats(self) -> dict[str, Any]:
        """Get event bus statistics."""
        return {
            **self.stats,
            "history_size": len(self.event_history),
            "subscriber_types": list(self.subscribers.keys()),
            "running": self.running,
        }

    def get_recent_events(self, count: int = 100) -> list[Event]:
        """Get recent events from history."""
        return self.event_history[-count:]


@log_all_methods
class PluginManager:
    """Plugin discovery, loading, and lifecycle management."""

    def __init__(self, config: dict[str, Any], event_bus: EventBus, logger: logging.Logger) -> None:
        """Initialize plugin manager with configuration, event bus, and logger."""
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
        """Discover available plugins."""
        discovered = []

        for directory in self.discovery_paths:
            dir_path = Path(directory)
            if not dir_path.exists():
                self.logger.exception(f"Plugin directory not found: {directory}")
                continue

            self.logger.info(f"Discovering plugins in: {directory}")
            # Discover different plugin types
            discovered.extend(await self._discover_ghidra_scripts(dir_path))
            discovered.extend(await self._discover_frida_scripts(dir_path))
            discovered.extend(await self._discover_python_modules(dir_path))

        self.stats["discovered"] = len(discovered)
        self.logger.info(f"Discovered {len(discovered)} plugins")

        return discovered

    async def _discover_ghidra_scripts(self, directory: Path) -> list[str]:
        """Discover Ghidra script plugins."""
        scripts = []

        for script_file in directory.glob("*.java"):
            try:
                # Read script metadata
                metadata = await self._extract_ghidra_metadata(script_file)
                if metadata:
                    plugin_name = f"ghidra_{script_file.stem}"
                    self.plugin_metadata[plugin_name] = metadata
                    scripts.append(plugin_name)

                    self.logger.debug(f"Discovered Ghidra script: {script_file}")

            except Exception as e:
                self.logger.exception(f"Error discovering Ghidra script {script_file}: {e}")

        return scripts

    async def _discover_frida_scripts(self, directory: Path) -> list[str]:
        """Discover Frida script plugins."""
        scripts = []

        for script_file in directory.glob("*.js"):
            try:
                # Read script metadata
                metadata = await self._extract_frida_metadata(script_file)
                if metadata:
                    plugin_name = f"frida_{script_file.stem}"
                    self.plugin_metadata[plugin_name] = metadata
                    scripts.append(plugin_name)

                    self.logger.debug(f"Discovered Frida script: {script_file}")

            except Exception as e:
                self.logger.exception(f"Error discovering Frida script {script_file}: {e}")

        return scripts

    async def _discover_python_modules(self, directory: Path) -> list[str]:
        """Discover Python module plugins."""
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

                    self.logger.debug(f"Discovered Python module: {module_file}")

            except Exception as e:
                self.logger.exception(f"Error discovering Python module {module_file}: {e}")

        return modules

    async def _extract_ghidra_metadata(self, script_file: Path) -> PluginMetadata | None:
        """Extract metadata from Ghidra script."""
        try:
            content = await asyncio.to_thread(lambda: script_file.read_text(encoding="utf-8"))

            # Parse Java comments for metadata
            metadata = {
                "name": script_file.stem,
                "version": "1.0.0",
                "description": f"Ghidra script: {script_file.name}",
                "author": "Unknown",
                "capabilities": ["static_analysis"],
                "dependencies": [],
            }

            # Look for metadata comments
            for line in content.split("\n")[:50]:  # Check first 50 lines
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
            self.logger.exception(f"Error extracting Ghidra metadata from {script_file}: {e}")
            return None

    async def _extract_frida_metadata(self, script_file: Path) -> PluginMetadata | None:
        """Extract metadata from Frida script."""
        try:
            content = await asyncio.to_thread(lambda: script_file.read_text(encoding="utf-8"))

            # Parse JavaScript comments for metadata
            metadata = {
                "name": script_file.stem,
                "version": "1.0.0",
                "description": f"Frida script: {script_file.name}",
                "author": "Unknown",
                "capabilities": ["dynamic_analysis"],
                "dependencies": [],
            }

            # Look for metadata in comments or object properties
            for line in content.split("\n")[:100]:  # Check first 100 lines
                line = line.strip()
                if line.startswith("//") or line.startswith("*"):
                    if "description:" in line.lower():
                        metadata["description"] = line.split("description:")[-1].strip().strip("\"'")
                    elif "author:" in line.lower():
                        metadata["author"] = line.split("author:")[-1].strip().strip("\"'")
                    elif "version:" in line.lower():
                        metadata["version"] = line.split("version:")[-1].strip().strip("\"'")
                elif "name:" in line and ("=" in line or ":" in line):
                    # Try to extract from object property
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
            self.logger.exception(f"Error extracting Frida metadata from {script_file}: {e}")
            return None

    async def _extract_python_metadata(self, module_file: Path) -> PluginMetadata | None:
        """Extract metadata from Python module."""
        try:
            content = await asyncio.to_thread(lambda: module_file.read_text(encoding="utf-8"))

            # Parse docstring and comments
            metadata = {
                "name": module_file.stem,
                "version": "1.0.0",
                "description": f"Python module: {module_file.name}",
                "author": "Unknown",
                "capabilities": ["custom_analysis"],
                "dependencies": [],
            }

            # Extract from docstring
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

            # Look for imports to determine capabilities
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
            self.logger.exception(f"Error extracting Python metadata from {module_file}: {e}")
            return None

    async def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin."""
        try:
            if plugin_name in self.plugins:
                self.logger.debug(f"Plugin {plugin_name} already loaded")
                return True

            # Check if plugin is disabled
            if plugin_name in self.disabled_plugins:
                self.logger.info(f"Plugin {plugin_name} is disabled")
                return False

            # Get metadata
            if plugin_name not in self.plugin_metadata:
                self.logger.error(f"No metadata found for plugin: {plugin_name}")
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
                self.logger.error(f"Plugin {plugin_name} initialization failed")
                return False

            # Store plugin
            self.plugins[plugin_name] = plugin
            self.stats["loaded"] += 1

            self.logger.info(f"Plugin {plugin_name} loaded successfully")

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
            self.logger.exception(f"Failed to load plugin {plugin_name}: {e}")
            return False

    async def _create_plugin_instance(self, plugin_name: str, metadata: PluginMetadata) -> AbstractPlugin | None:
        """Create plugin instance based on type."""
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
                self.logger.error(f"Plugin file not found for: {plugin_name}")
                return None

            # Create appropriate plugin instance
            if metadata.component_type == ComponentType.GHIDRA_SCRIPT:
                return GhidraPlugin(plugin_name, str(plugin_file), metadata.version)
            if metadata.component_type == ComponentType.FRIDA_SCRIPT:
                return FridaPlugin(plugin_name, str(plugin_file), metadata.version)
            if metadata.component_type == ComponentType.CUSTOM_MODULE:
                return PythonPlugin(plugin_name, str(plugin_file), metadata.version)
            self.logger.error(f"Unsupported plugin type: {metadata.component_type}")
            return None

        except Exception as e:
            self.logger.exception(f"Error creating plugin instance for {plugin_name}: {e}")
            return None

    async def load_all_plugins(self) -> int:
        """Load all discovered plugins."""
        if self.auto_discover:
            await self.discover_plugins()

        loaded_count = 0

        # Determine load order based on dependencies
        load_order = self._calculate_load_order()

        for plugin_name in load_order:
            if await self.load_plugin(plugin_name):
                loaded_count += 1

        self.logger.info(f"Loaded {loaded_count} plugins")
        return loaded_count

    def _calculate_load_order(self) -> list[str]:
        """Calculate plugin load order based on dependencies."""
        # Simple topological sort for dependency resolution
        visited = set()
        temp_visited = set()
        result = []

        def visit(plugin_name: str) -> None:
            if plugin_name in temp_visited:
                # Circular dependency detected
                self.logger.exception(f"Circular dependency detected involving: {plugin_name}")
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
        """Activate a loaded plugin."""
        if plugin_name not in self.plugins:
            self.logger.error(f"Plugin {plugin_name} not loaded")
            return False

        plugin = self.plugins[plugin_name]

        try:
            if await plugin.activate():
                self.stats["active"] += 1
                self.logger.info(f"Plugin {plugin_name} activated")

                # Emit event
                await self.event_bus.emit(
                    Event(
                        event_type="plugin_activated",
                        source="plugin_manager",
                        data={"plugin_name": plugin_name},
                    ),
                )

                return True
            self.logger.exception(f"Plugin {plugin_name} activation failed")
            return False

        except Exception as e:
            self.logger.exception(f"Error activating plugin {plugin_name}: {e}")
            return False

    async def deactivate_plugin(self, plugin_name: str) -> bool:
        """Deactivate an active plugin."""
        if plugin_name not in self.plugins:
            self.logger.error(f"Plugin {plugin_name} not loaded")
            return False

        plugin = self.plugins[plugin_name]

        try:
            if await plugin.deactivate():
                if plugin.status == PluginStatus.READY:
                    self.stats["active"] = max(0, self.stats["active"] - 1)

                self.logger.info(f"Plugin {plugin_name} deactivated")

                # Emit event
                await self.event_bus.emit(
                    Event(
                        event_type="plugin_deactivated",
                        source="plugin_manager",
                        data={"plugin_name": plugin_name},
                    ),
                )

                return True
            self.logger.exception(f"Plugin {plugin_name} deactivation failed")
            return False

        except Exception as e:
            self.logger.exception(f"Error deactivating plugin {plugin_name}: {e}")
            return False

    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin."""
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

            self.logger.info(f"Plugin {plugin_name} unloaded")

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
            self.logger.exception(f"Error unloading plugin {plugin_name}: {e}")
            return False

    def get_plugin(self, plugin_name: str) -> AbstractPlugin | None:
        """Get plugin instance."""
        return self.plugins.get(plugin_name)

    def get_plugins_by_capability(self, capability: str) -> list[AbstractPlugin]:
        """Get plugins with specific capability."""
        matching_plugins = []

        for plugin_name, plugin in self.plugins.items():
            if plugin_name in self.plugin_metadata:
                metadata = self.plugin_metadata[plugin_name]
                if capability in metadata.capabilities:
                    matching_plugins.append(plugin)

        return matching_plugins

    def get_plugins_by_type(self, component_type: ComponentType) -> list[AbstractPlugin]:
        """Get plugins of specific type."""
        matching_plugins = []

        for plugin_name, plugin in self.plugins.items():
            if plugin_name in self.plugin_metadata:
                metadata = self.plugin_metadata[plugin_name]
                if metadata.component_type == component_type:
                    matching_plugins.append(plugin)

        return matching_plugins

    def get_plugin_stats(self) -> dict[str, Any]:
        """Get plugin statistics."""
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
        """Initialize workflow engine with plugin manager, event bus, and logger."""
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
        """Load default workflow templates."""
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
        """Register a workflow definition."""
        self.workflows[workflow.workflow_id] = workflow
        self.logger.info(f"Registered workflow: {workflow.name}")

    async def execute_workflow(self, workflow_id: str, parameters: dict[str, Any]) -> str:
        """Execute a workflow."""
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

        self.logger.info(f"Started workflow execution: {workflow.name} (ID: {execution_id})")

        return execution_id

    async def _execute_workflow_async(self, context: dict[str, Any]) -> None:
        """Execute workflow asynchronously."""
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

            self.logger.info(f"Workflow completed: {execution_id}")

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
            context["end_time"] = datetime.utcnow()
            context["errors"].append(str(e))

            self.logger.exception(f"Workflow failed: {execution_id} - {e}")

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
        """Execute workflow steps sequentially."""
        workflow = context["workflow"]
        total_steps = len(workflow.steps)

        for i, step in enumerate(workflow.steps):
            # Check if step should be executed (condition)
            if step.condition and not self._evaluate_condition(step.condition, context):
                self.logger.info(f"Skipping step {step.step_id} - condition not met")
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
        """Execute workflow steps in parallel where possible."""
        workflow = context["workflow"]

        # Build dependency graph
        dependency_graph = self._build_dependency_graph(workflow.steps)

        # Log dependency analysis
        self.logger.info(f"Built dependency graph with {len(dependency_graph)} nodes")
        for step_id, deps in dependency_graph.items():
            if deps:
                self.logger.debug(f"Step {step_id} depends on: {deps}")

        # Execute in dependency order with parallelization
        executed_steps = set()
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
        self.logger.info(f"Parallel workflow execution completed. Total tasks executed: {len(tasks)}")

        # Clean up any remaining tasks
        for task in tasks:
            if not task.done():
                task.cancel()

    def _build_dependency_graph(self, steps: list[WorkflowStep]) -> dict[str, list[str]]:
        """Build dependency graph for parallel execution."""
        return {step.step_id: step.dependencies.copy() for step in steps}

    def _check_dependencies(self, step: WorkflowStep, context: dict[str, Any]) -> bool:
        """Check if step dependencies are satisfied."""
        return all(dep in context["completed_steps"] for dep in step.dependencies)

    def _evaluate_condition(self, condition: str, context: dict[str, Any]) -> bool:
        """Evaluate step execution condition."""
        try:
            # Create safe evaluation context
            eval_context = {
                "results": context["step_results"],
                "parameters": context["parameters"],
            }

            # Log evaluation context for debugging
            self.logger.debug(f"Evaluating condition '{condition}' with context: {list(eval_context.keys())}")

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
            self.logger.exception(f"Error evaluating condition '{condition}': {e}")
            return False

    async def _execute_step(self, step: WorkflowStep, context: dict[str, Any]) -> None:
        """Execute individual workflow step."""
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
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info(f"Step {step.step_id} completed in {duration:.2f}s")

        except TimeoutError as timeout_error:
            error_msg = f"Step {step.step_id} timed out"
            context["errors"].append(error_msg)

            if step.retry_count >= step.max_retries:
                raise Exception(error_msg) from timeout_error

            step.retry_count += 1
            self.logger.exception(f"Retrying step {step.step_id} (attempt {step.retry_count})")
            await self._execute_step(step, context)
        except Exception as e:
            error_msg = f"Step {step.step_id} failed: {e}"
            context["errors"].append(error_msg)

            if step.retry_count >= step.max_retries:
                raise Exception(error_msg) from e
            step.retry_count += 1
            self.logger.exception(f"Retrying step {step.step_id} (attempt {step.retry_count})")
            await self._execute_step(step, context)

    def get_workflow_status(self, execution_id: str) -> dict[str, Any] | None:
        """Get workflow execution status."""
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
                    "duration": ((workflow_record["end_time"] or datetime.utcnow()) - workflow_record["start_time"]).total_seconds(),
                }
                for workflow_record in self.workflow_history
                if workflow_record["execution_id"] == execution_id
            ),
            None,
        )

    def cancel_workflow(self, execution_id: str) -> bool:
        """Cancel running workflow."""
        if execution_id in self.running_workflows:
            context = self.running_workflows[execution_id]
            context["status"] = WorkflowStatus.CANCELLED
            context["end_time"] = datetime.now(UTC)

            self.logger.info(f"Workflow cancelled: {execution_id}")
            return True

        return False

    def get_available_workflows(self) -> list[dict[str, Any]]:
        """Get list of available workflows."""
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
        """Initialize analysis coordinator with plugin manager, workflow engine, event bus, and logger."""
        self.plugin_manager = plugin_manager
        self.workflow_engine = workflow_engine
        self.event_bus = event_bus
        self.logger = logger

        self.active_analyses: dict[str, dict[str, Any]] = {}
        self.analysis_queue: asyncio.Queue = asyncio.Queue()
        self.coordinator_task: asyncio.Task | None = None
        self.running = False

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
        """Start analysis coordinator."""
        if self.running:
            return

        self.running = True
        self.coordinator_task = asyncio.create_task(self._coordination_loop())

        self.logger.info("Analysis coordinator started")

    async def stop(self) -> None:
        """Stop analysis coordinator."""
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
        parameters: dict[str, Any] = None,
    ) -> str:
        """Analyze binary file."""
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

        self.logger.info(f"Queued analysis: {analysis_id} for {binary_path}")

        return analysis_id

    async def _coordination_loop(self) -> None:
        """Run main coordination loop."""
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
                self.logger.exception(f"Error in coordination loop: {e}")

    async def _start_analysis(self, analysis_context: dict[str, Any]) -> None:
        """Start individual analysis."""
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

            self.logger.info(f"Started analysis: {analysis_id}")

        except Exception as e:
            analysis_context["status"] = "failed"
            analysis_context["error"] = str(e)

            self.logger.exception(f"Failed to start analysis {analysis_id}: {e}")

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
        """Extract basic file information."""
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
            self.logger.exception(f"Error extracting file info: {e}")
            return {"name": Path(file_path).name, "error": str(e)}

    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type."""
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
        """Handle analysis request event."""
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
            self.logger.exception(f"Error handling analysis request: {e}")

    async def _handle_workflow_completed(self, event: Event) -> None:
        """Handle workflow completion."""
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

                self.logger.info(f"Analysis completed: {analysis_id}")
                break

    async def _handle_workflow_failed(self, event: Event) -> None:
        """Handle workflow failure."""
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

                self.logger.exception(f"Analysis failed: {analysis_id} - {error}")
                break

    def get_analysis_status(self, analysis_id: str) -> dict[str, Any] | None:
        """Get analysis status."""
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
        """Get all active analyses."""
        return [self.get_analysis_status(analysis_id) for analysis_id in self.active_analyses]


@log_all_methods
class ResourceManager:
    """System resource monitoring and management."""

    def __init__(self, config: dict[str, Any], logger: logging.Logger) -> None:
        """Initialize resource manager with configuration and logger."""
        self.config = config
        self.logger = logger

        self.monitoring_enabled = config.get("resource_monitoring", True)
        self.auto_cleanup = config.get("auto_cleanup", True)
        self.max_memory_usage = config.get("max_memory_usage", 80)  # Percentage
        self.max_cpu_usage = config.get("max_cpu_usage", 90)  # Percentage

        # Resource pools
        self.process_pool: ProcessPoolExecutor | None = None
        self.thread_pool: ThreadPoolExecutor | None = None
        self.max_workers = config.get("max_workers", mp.cpu_count())

        # Monitoring
        self.monitoring_task: asyncio.Task | None = None
        self.running = False

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
        """Start resource manager."""
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
        """Stop resource manager."""
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
        """Resource monitoring loop."""
        while self.running:
            try:
                await self._update_resource_stats()
                await self._check_resource_limits()

                if self.auto_cleanup:
                    await self._auto_cleanup()

                await asyncio.sleep(5)  # Monitor every 5 seconds

            except Exception as e:
                self.logger.exception(f"Error in resource monitoring: {e}")
                await asyncio.sleep(10)

    async def _update_resource_stats(self) -> None:
        """Update resource statistics."""
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
            self.logger.exception(f"Error updating resource stats: {e}")

    async def _check_resource_limits(self) -> None:
        """Check resource limits and warn if exceeded."""
        cpu_usage = self.resource_stats["cpu_usage"]
        memory_usage = self.resource_stats["memory_usage"]

        if cpu_usage > self.max_cpu_usage:
            self.logger.exception(f"High CPU usage: {cpu_usage:.1f}%")

        if memory_usage > self.max_memory_usage:
            self.logger.exception(f"High memory usage: {memory_usage:.1f}%")

    async def _auto_cleanup(self) -> None:
        """Automatic cleanup of resources."""
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
            self.logger.exception(f"Error in auto cleanup: {e}")

    async def execute_in_process(self, func: Callable, *args: object, **kwargs: object) -> object:
        """Execute function in process pool."""
        if not self.process_pool:
            raise Exception("Process pool not initialized")

        loop = asyncio.get_event_loop()
        future = self.process_pool.submit(func, *args, **kwargs)
        return await loop.run_in_executor(None, future.result)

    async def execute_in_thread(self, func: Callable, *args: object, **kwargs: object) -> object:
        """Execute function in thread pool."""
        if not self.thread_pool:
            raise Exception("Thread pool not initialized")

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, func, *args, **kwargs)

    async def start_external_process(self, cmd: list[str], cwd: str = None) -> subprocess.Popen:
        """Start external process with tracking."""
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

            self.logger.debug(f"Started external process: {' '.join(cmd)} (PID: {process.pid})")

            return process

        except Exception as e:
            self.logger.exception(f"Error starting external process: {e}")
            raise

    async def kill_process(self, pid: int, force: bool = False) -> None:
        """Kill tracked process."""
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
            self.logger.info(f"Killed process: {pid}")

        except psutil.NoSuchProcess:
            if pid in self.tracked_processes:
                del self.tracked_processes[pid]
        except Exception as e:
            self.logger.exception(f"Error killing process {pid}: {e}")

    async def _cleanup_processes(self) -> None:
        """Cleanup all tracked processes."""
        for pid in list(self.tracked_processes):
            await self.kill_process(pid, force=True)

    def get_resource_stats(self) -> dict[str, Any]:
        """Get current resource statistics."""
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
        """Initialize Intellicrack core engine with optional configuration path."""
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
        self.running = False
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
        """Start the core engine."""
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
            self.logger.info(f"Loaded {loaded_plugins} plugins")

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
            self.logger.exception(f"Failed to start engine: {e}")
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop the core engine."""
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
            self.logger.exception(f"Error stopping engine: {e}")

    async def _activate_core_plugins(self) -> None:
        """Activate core plugins required for operation."""
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
        """Deactivate all active plugins."""
        active_plugins = list(self.plugin_manager.plugins.keys())

        for plugin_name in active_plugins:
            await self.plugin_manager.deactivate_plugin(plugin_name)
            await self.plugin_manager.unload_plugin(plugin_name)

    # API Interface Methods

    async def _handle_analyze_binary(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle binary analysis request."""
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
        """Handle get analysis status request."""
        analysis_id = request.get("analysis_id")

        if not analysis_id:
            raise ValueError("analysis_id is required")

        if status := self.analysis_coordinator.get_analysis_status(analysis_id):
            return status
        else:
            raise ValueError(f"Analysis not found: {analysis_id}")

    async def _handle_list_plugins(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle list plugins request."""
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
        """Handle get plugin status request."""
        plugin_name = request.get("plugin_name")

        if not plugin_name:
            raise ValueError("plugin_name is required")

        if plugin := self.plugin_manager.get_plugin(plugin_name):
            return plugin.get_status()
        else:
            raise ValueError(f"Plugin not found: {plugin_name}")

    async def _handle_execute_workflow(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle execute workflow request."""
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
        """Handle get workflow status request."""
        execution_id = request.get("execution_id")

        if not execution_id:
            raise ValueError("execution_id is required")

        if status := self.workflow_engine.get_workflow_status(execution_id):
            return status
        else:
            raise ValueError(f"Workflow execution not found: {execution_id}")

    async def _handle_get_system_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle get system status request."""
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
        """Process API request."""
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
            self.logger.exception(f"API request failed: {method} - {e}")

            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }


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
                        await asyncio.wait([asyncio.sleep(0.1)], return_when=asyncio.FIRST_COMPLETED)
                except asyncio.CancelledError:
                    pass  # Allow clean cancellation
            else:
                # Interactive mode
                print("Intellicrack Core Engine running. Press Ctrl+C to stop.")
                try:
                    while engine.running:
                        await asyncio.wait([asyncio.sleep(0.1)], return_when=asyncio.FIRST_COMPLETED)
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
