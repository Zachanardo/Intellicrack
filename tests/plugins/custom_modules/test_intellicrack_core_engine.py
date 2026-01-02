"""Comprehensive production-grade tests for Intellicrack Core Engine.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

Tests validate real core engine orchestration capabilities for license cracking operations:
- Plugin discovery, loading, and lifecycle management for license bypass plugins
- Event bus communication for coordination of cracking workflows
- Workflow execution for multi-step license defeat operations
- Analysis coordination for binary protection detection
- Resource management and process tracking
- Configuration management with validation
- Logging infrastructure with structured output
- Real component integration (NO mocks for core functionality)
"""

import asyncio
import json
import logging
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

try:
    from intellicrack.plugins.custom_modules.intellicrack_core_engine import (
        AbstractPlugin,
        AnalysisCoordinator,
        ComponentType,
        ConfigurationManager,
        Event,
        EventBus,
        EventPriority,
        FridaPlugin,
        GhidraPlugin,
        IntellicrackcoreEngine,
        JSONFormatter,
        LoggingManager,
        PluginManager,
        PluginMetadata,
        PluginStatus,
        PythonPlugin,
        ResourceManager,
        WorkflowDefinition,
        WorkflowEngine,
        WorkflowStatus,
        WorkflowStep,
    )

    CORE_ENGINE_AVAILABLE = True
except ImportError as e:
    CORE_ENGINE_AVAILABLE = False
    IMPORT_ERROR = str(e)

pytestmark = pytest.mark.skipif(
    not CORE_ENGINE_AVAILABLE,
    reason=f"Core engine not available: {'' if CORE_ENGINE_AVAILABLE else IMPORT_ERROR}",
)


@pytest.fixture
def temp_config_dir(tmp_path: Path) -> Path:
    """Create temporary configuration directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    return config_dir


@pytest.fixture
def temp_plugin_dir(tmp_path: Path) -> Path:
    """Create temporary plugin directory."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir(exist_ok=True)
    return plugin_dir


@pytest.fixture
def sample_config(temp_config_dir: Path) -> dict[str, Any]:
    """Create sample configuration for license cracking operations."""
    return {
        "logging": {
            "console_level": "INFO",
            "file_level": "DEBUG",
            "log_directory": str(temp_config_dir / "logs"),
            "max_log_size": 10485760,
            "backup_count": 3,
        },
        "plugins": {
            "directories": [str(temp_config_dir / "plugins")],
            "auto_discover": True,
            "auto_load": True,
            "load_timeout": 30,
            "enabled": [],
            "disabled": [],
        },
        "engine": {
            "max_workers": 4,
            "max_concurrent_workflows": 5,
            "default_timeout": 300,
            "resource_monitoring": True,
            "auto_cleanup": True,
        },
        "tools": {
            "ghidra_path": "/opt/ghidra",
            "frida_path": "frida",
            "radare2_path": "r2",
            "java_path": "java",
            "node_path": "node",
        },
        "analysis": {
            "temp_directory": str(temp_config_dir / "temp"),
            "max_file_size": 1073741824,
            "supported_formats": [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"],
            "default_analysis_timeout": 600,
        },
    }


@pytest.fixture
def config_file(temp_config_dir: Path, sample_config: dict[str, Any]) -> Path:
    """Create configuration file on disk."""
    config_path = temp_config_dir / "intellicrack.json"
    with open(config_path, "w") as f:
        json.dump(sample_config, f, indent=2)
    return config_path


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary for testing license cracking."""
    binary = tmp_path / "protected_app.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary


class TestEnumerations:
    """Test enumeration types used throughout core engine."""

    def test_component_type_contains_all_plugin_types(self) -> None:
        """ComponentType enum includes all supported plugin types."""
        assert hasattr(ComponentType, "GHIDRA_SCRIPT")
        assert hasattr(ComponentType, "FRIDA_SCRIPT")
        assert hasattr(ComponentType, "RADARE2_MODULE")
        assert hasattr(ComponentType, "ML_MODULE")
        assert hasattr(ComponentType, "CUSTOM_MODULE")
        assert hasattr(ComponentType, "BYPASS_COMPONENT")
        assert hasattr(ComponentType, "ANALYSIS_TOOL")
        assert hasattr(ComponentType, "UI_COMPONENT")

    def test_plugin_status_tracks_complete_lifecycle(self) -> None:
        """PluginStatus enum covers full plugin lifecycle."""
        statuses = [status.value for status in PluginStatus]

        assert "discovered" in statuses
        assert "loading" in statuses
        assert "loaded" in statuses
        assert "ready" in statuses
        assert "active" in statuses
        assert "error" in statuses

    def test_event_priority_has_correct_ordering(self) -> None:
        """EventPriority levels are correctly ordered for event processing."""
        assert EventPriority.CRITICAL.value < EventPriority.HIGH.value
        assert EventPriority.HIGH.value < EventPriority.MEDIUM.value
        assert EventPriority.MEDIUM.value < EventPriority.LOW.value

    def test_workflow_status_represents_execution_states(self) -> None:
        """WorkflowStatus includes all workflow execution states."""
        assert WorkflowStatus.PENDING.value == "pending"
        assert WorkflowStatus.RUNNING.value == "running"
        assert WorkflowStatus.COMPLETED.value == "completed"
        assert WorkflowStatus.FAILED.value == "failed"
        assert WorkflowStatus.CANCELLED.value == "cancelled"


class TestPluginMetadata:
    """Test PluginMetadata data structure for plugin information."""

    def test_metadata_creation_with_required_fields(self) -> None:
        """Create plugin metadata with required fields for license bypass plugin."""
        metadata = PluginMetadata(
            name="license_patcher",
            version="1.0.0",
            description="Binary patcher for license validation bypass",
            component_type=ComponentType.BYPASS_COMPONENT,
        )

        assert metadata.name == "license_patcher"
        assert metadata.version == "1.0.0"
        assert metadata.component_type == ComponentType.BYPASS_COMPONENT
        assert metadata.dependencies == []
        assert metadata.capabilities == []

    def test_metadata_with_full_license_bypass_capabilities(self) -> None:
        """Create metadata with complete license bypass capabilities."""
        metadata = PluginMetadata(
            name="advanced_keygen",
            version="2.0.0",
            description="Advanced serial key generator",
            component_type=ComponentType.CUSTOM_MODULE,
            author="Security Research Team",
            license="GPL-3.0",
            dependencies=["crypto_analyzer"],
            capabilities=["keygen", "serial_validation", "rsa_cracking"],
            supported_formats=[".exe", ".dll"],
            tags=["licensing", "keygen", "serial"],
        )

        assert len(metadata.capabilities) == 3
        assert "keygen" in metadata.capabilities
        assert "serial_validation" in metadata.capabilities
        assert metadata.author == "Security Research Team"

    def test_metadata_serializes_to_dictionary(self) -> None:
        """Plugin metadata converts to dictionary for storage and transmission."""
        metadata = PluginMetadata(
            name="trial_resetter",
            version="1.5.0",
            description="Trial period reset plugin",
            component_type=ComponentType.CUSTOM_MODULE,
            capabilities=["trial_reset", "registry_manipulation"],
        )

        result = metadata.to_dict()

        assert isinstance(result, dict)
        assert result["name"] == "trial_resetter"
        assert result["version"] == "1.5.0"
        assert result["component_type"] == "custom_module"
        assert len(result["capabilities"]) == 2


class TestEventStructures:
    """Test Event data structures for inter-component communication."""

    def test_event_creation_for_license_bypass_operation(self) -> None:
        """Create event for license bypass operation with auto-generated ID."""
        event = Event(
            event_type="license_validation_bypassed",
            source="license_patcher",
            data={"binary": "target.exe", "offset": 0x12000, "patch_size": 5},
        )

        assert event.event_type == "license_validation_bypassed"
        assert event.source == "license_patcher"
        assert event.event_id is not None
        assert len(event.event_id) > 0
        assert event.data["offset"] == 0x12000

    def test_event_with_target_and_priority(self) -> None:
        """Create targeted event with priority for workflow coordination."""
        event = Event(
            event_type="protection_detected",
            source="static_analyzer",
            target="bypass_coordinator",
            priority=EventPriority.CRITICAL,
            data={"protection_type": "VMProtect", "version": "3.5"},
        )

        assert event.target == "bypass_coordinator"
        assert event.priority == EventPriority.CRITICAL
        assert event.data["protection_type"] == "VMProtect"

    def test_event_with_ttl_expiration(self) -> None:
        """Create event with time-to-live for time-sensitive operations."""
        event = Event(
            event_type="temp_license_created",
            source="license_emulator",
            data={"license_key": "TEMP-KEY", "expires": "2024-12-31"},
            ttl=3600,
        )

        assert event.ttl == 3600

    def test_event_serialization_to_dictionary(self) -> None:
        """Event serializes to dictionary for network transmission."""
        event = Event(
            event_type="keygen_completed",
            source="keygen_plugin",
            data={"serial": "XXXX-YYYY-ZZZZ", "algorithm": "RSA-2048"},
            correlation_id="workflow_456",
        )

        result = event.to_dict()

        assert isinstance(result, dict)
        assert result["event_type"] == "keygen_completed"
        assert result["correlation_id"] == "workflow_456"
        assert "timestamp" in result


class TestWorkflowStructures:
    """Test workflow definition structures for license cracking operations."""

    def test_workflow_step_for_license_bypass(self) -> None:
        """Create workflow step for license bypass operation."""
        step = WorkflowStep(
            step_id="patch_validation",
            name="Patch License Validation",
            plugin_name="binary_patcher",
            method="patch_license_check",
            parameters={"binary_path": "/target/app.exe", "validation_offset": 0x1000},
            dependencies=["analyze_protection"],
            timeout=120,
            max_retries=3,
        )

        assert step.step_id == "patch_validation"
        assert step.plugin_name == "binary_patcher"
        assert step.method == "patch_license_check"
        assert "analyze_protection" in step.dependencies
        assert step.timeout == 120

    def test_workflow_step_with_conditional_execution(self) -> None:
        """Create conditional workflow step for optional bypass operations."""
        step = WorkflowStep(
            step_id="emulate_dongle",
            name="Emulate Hardware Dongle",
            plugin_name="dongle_emulator",
            method="start_emulation",
            condition="analyze_protection.has_hardware_dongle",
        )

        assert step.condition == "analyze_protection.has_hardware_dongle"

    def test_workflow_definition_for_complete_bypass(self) -> None:
        """Create complete workflow definition for license bypass."""
        steps = [
            WorkflowStep(
                step_id="detect_protection",
                name="Detect Protection Scheme",
                plugin_name="protection_detector",
                method="detect",
            ),
            WorkflowStep(
                step_id="analyze_license",
                name="Analyze License Validation",
                plugin_name="license_analyzer",
                method="analyze",
                dependencies=["detect_protection"],
            ),
            WorkflowStep(
                step_id="generate_key",
                name="Generate Valid Key",
                plugin_name="keygen",
                method="generate",
                dependencies=["analyze_license"],
            ),
        ]

        workflow = WorkflowDefinition(
            workflow_id="complete_license_bypass",
            name="Complete License Bypass Workflow",
            description="Full automated license bypass from detection to key generation",
            steps=steps,
            parallel_execution=False,
            timeout=1800,
            error_handling="stop",
        )

        assert workflow.workflow_id == "complete_license_bypass"
        assert len(workflow.steps) == 3
        assert workflow.parallel_execution is False
        assert workflow.timeout == 1800


class TestLoggingManager:
    """Test LoggingManager for structured logging infrastructure."""

    def test_logging_manager_initialization(self, sample_config: dict[str, Any]) -> None:
        """LoggingManager initializes with configuration."""
        manager = LoggingManager(sample_config["logging"])

        assert manager.config == sample_config["logging"]
        assert "console" in manager.handlers
        assert "file" in manager.handlers
        assert "json" in manager.handlers

    def test_logging_manager_creates_component_loggers(self, sample_config: dict[str, Any]) -> None:
        """LoggingManager provides loggers for framework components."""
        manager = LoggingManager(sample_config["logging"])

        bypass_logger = manager.get_logger("license_bypass")
        keygen_logger = manager.get_logger("keygen")

        assert bypass_logger is not None
        assert keygen_logger is not None
        assert bypass_logger.name == "intellicrack.license_bypass"

    def test_logging_manager_logs_events(self, sample_config: dict[str, Any]) -> None:
        """LoggingManager logs events with structured data."""
        manager = LoggingManager(sample_config["logging"])

        event = Event(
            event_type="license_bypassed",
            source="patcher",
            data={"success": True, "patches": 3},
        )

        manager.log_event(event)

    def test_logging_manager_logs_plugin_operations(self, sample_config: dict[str, Any]) -> None:
        """LoggingManager logs plugin operations with details."""
        manager = LoggingManager(sample_config["logging"])

        manager.log_plugin_operation(
            "license_patcher",
            "patch_binary",
            "success",
            {"patches_applied": 5, "binary": "target.exe"},
        )


class TestJSONFormatter:
    """Test JSONFormatter for structured JSON logging."""

    def test_json_formatter_creates_valid_json(self) -> None:
        """JSONFormatter produces valid JSON log entries."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=100,
            msg="License check bypassed at offset 0x1000",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["level"] == "INFO"
        assert "License check bypassed" in parsed["message"]
        assert parsed["line"] == 100

    def test_json_formatter_includes_extra_fields(self) -> None:
        """JSONFormatter includes extra fields in JSON output."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name="bypass",
            level=logging.INFO,
            pathname="bypass.py",
            lineno=200,
            msg="Protection detected",
            args=(),
            exc_info=None,
        )
        record.protection_type = "VMProtect"
        record.binary_path = "target.exe"

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["protection_type"] == "VMProtect"
        assert parsed["binary_path"] == "target.exe"


class TestConfigurationManager:
    """Test ConfigurationManager for configuration handling."""

    def test_configuration_manager_creates_default_config(self, temp_config_dir: Path) -> None:
        """ConfigurationManager creates default configuration if none exists."""
        config_path = temp_config_dir / "new_config.json"
        manager = ConfigurationManager(str(config_path))

        assert manager.config is not None
        assert "logging" in manager.config
        assert "plugins" in manager.config
        assert "engine" in manager.config
        assert config_path.exists()

    def test_configuration_manager_loads_existing_config(self, config_file: Path, sample_config: dict[str, Any]) -> None:
        """ConfigurationManager loads existing configuration from file."""
        manager = ConfigurationManager(str(config_file))

        assert manager.config["logging"]["console_level"] == "INFO"
        assert manager.config["engine"]["max_workers"] == 4

    def test_configuration_manager_get_with_dot_notation(self, config_file: Path) -> None:
        """ConfigurationManager retrieves values using dot notation."""
        manager = ConfigurationManager(str(config_file))

        console_level = manager.get("logging.console_level")
        max_workers = manager.get("engine.max_workers")

        assert console_level == "INFO"
        assert max_workers == 4

    def test_configuration_manager_set_updates_value(self, config_file: Path) -> None:
        """ConfigurationManager updates configuration values."""
        manager = ConfigurationManager(str(config_file))

        manager.set("engine.max_workers", 8)

        assert manager.get("engine.max_workers") == 8

    def test_configuration_manager_watcher_notifications(self, config_file: Path) -> None:
        """ConfigurationManager notifies watchers of configuration changes."""
        manager = ConfigurationManager(str(config_file))

        callback_called = False
        received_config = None

        def watcher(config: dict[str, Any]) -> None:
            nonlocal callback_called, received_config
            callback_called = True
            received_config = config

        manager.add_watcher(watcher)
        manager.reload_config()

        assert callback_called
        assert received_config is not None


class TestEventBus:
    """Test EventBus for inter-component event communication."""

    @pytest.mark.asyncio
    async def test_event_bus_starts_and_stops(self) -> None:
        """EventBus starts event processing loop and stops cleanly."""
        event_bus = EventBus()

        assert event_bus.running is False

        await event_bus.start()
        assert event_bus.running is True

        await event_bus.stop()
        assert event_bus.running is False

    @pytest.mark.asyncio
    async def test_event_bus_delivers_events_to_subscribers(self) -> None:
        """EventBus delivers events to subscribed handlers."""
        event_bus = EventBus()
        await event_bus.start()

        received_events = []

        async def handler(event: Event) -> None:
            received_events.append(event)

        event_bus.subscribe("license_bypassed", handler)

        test_event = Event(
            event_type="license_bypassed",
            source="patcher",
            data={"success": True},
        )

        await event_bus.emit(test_event)
        await asyncio.sleep(0.2)

        assert len(received_events) == 1
        assert received_events[0].event_type == "license_bypassed"

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_multiple_subscribers_receive_same_event(self) -> None:
        """EventBus delivers events to all subscribers simultaneously."""
        event_bus = EventBus()
        await event_bus.start()

        handler1_called = False
        handler2_called = False

        async def handler1(event: Event) -> None:
            nonlocal handler1_called
            handler1_called = True

        async def handler2(event: Event) -> None:
            nonlocal handler2_called
            handler2_called = True

        event_bus.subscribe("keygen_complete", handler1)
        event_bus.subscribe("keygen_complete", handler2)

        await event_bus.emit(
            Event(event_type="keygen_complete", source="keygen", data={"key": "TEST"}),
        )
        await asyncio.sleep(0.2)

        assert handler1_called
        assert handler2_called

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_unsubscribe_stops_delivery(self) -> None:
        """EventBus stops delivering events after unsubscribe."""
        event_bus = EventBus()
        await event_bus.start()

        handler_count = 0

        async def handler(event: Event) -> None:
            nonlocal handler_count
            handler_count += 1

        event_bus.subscribe("test_event", handler)

        await event_bus.emit(Event(event_type="test_event", source="test"))
        await asyncio.sleep(0.1)
        first_count = handler_count

        event_bus.unsubscribe("test_event", handler)

        await event_bus.emit(Event(event_type="test_event", source="test"))
        await asyncio.sleep(0.1)

        assert handler_count == first_count

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_respects_ttl_expiration(self) -> None:
        """EventBus respects event TTL and drops expired events."""
        event_bus = EventBus()
        await event_bus.start()

        received = False

        async def handler(event: Event) -> None:
            nonlocal received
            received = True

        event_bus.subscribe("test_event", handler)

        expired_event = Event(
            event_type="test_event",
            source="test",
            timestamp=datetime.now(UTC) - timedelta(seconds=100),
            ttl=10,
        )

        await event_bus.emit(expired_event)
        await asyncio.sleep(0.2)

        assert not received

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_wildcard_subscription(self) -> None:
        """EventBus wildcard subscription receives all event types."""
        event_bus = EventBus()
        await event_bus.start()

        received_types = []

        async def wildcard_handler(event: Event) -> None:
            received_types.append(event.event_type)

        event_bus.subscribe("*", wildcard_handler)

        await event_bus.emit(Event(event_type="event1", source="test"))
        await event_bus.emit(Event(event_type="event2", source="test"))
        await asyncio.sleep(0.2)

        assert "event1" in received_types
        assert "event2" in received_types

        await event_bus.stop()


class TestResourceManager:
    """Test ResourceManager for system resource management."""

    @pytest.mark.asyncio
    async def test_resource_manager_starts_and_stops(self, sample_config: dict[str, Any]) -> None:
        """ResourceManager starts monitoring and stops cleanly."""
        logger = logging.getLogger("test")
        manager = ResourceManager(sample_config["engine"], logger)

        assert manager.running is False

        await manager.start()
        assert manager.running is True
        assert manager.process_pool is not None
        assert manager.thread_pool is not None

        await manager.stop()
        assert manager.running is False

    @pytest.mark.asyncio
    async def test_resource_manager_provides_resource_stats(self, sample_config: dict[str, Any]) -> None:
        """ResourceManager collects and provides system resource statistics."""
        logger = logging.getLogger("test")
        manager = ResourceManager(sample_config["engine"], logger)

        await manager.start()
        await asyncio.sleep(0.5)

        stats = manager.get_resource_stats()

        assert "cpu_usage" in stats
        assert "memory_usage" in stats
        assert stats["monitoring_enabled"] is True

        await manager.stop()


class TestIntellicrackcoreEngine:
    """Test IntellicrackcoreEngine main orchestration engine."""

    @pytest.mark.asyncio
    async def test_core_engine_initializes_all_components(self, config_file: Path) -> None:
        """CoreEngine initializes all required framework components."""
        engine = IntellicrackcoreEngine(str(config_file))

        assert engine.config_manager is not None
        assert engine.logging_manager is not None
        assert engine.event_bus is not None
        assert engine.resource_manager is not None
        assert engine.plugin_manager is not None
        assert engine.workflow_engine is not None
        assert engine.analysis_coordinator is not None

    @pytest.mark.asyncio
    async def test_core_engine_start_stop_lifecycle(self, config_file: Path, temp_plugin_dir: Path) -> None:
        """CoreEngine starts and stops all components correctly."""
        sample_plugin = temp_plugin_dir / "test_bypass.py"
        sample_plugin.write_text(
            '''"""Test bypass plugin."""

class Plugin:
    def initialize(self, config):
        return True

    def activate(self):
        return True

    def deactivate(self):
        return True

    def cleanup(self):
        return True

    def get_operations(self):
        return ["bypass"]

    def bypass(self, binary_path):
        return {"success": True}
''',
        )

        engine = IntellicrackcoreEngine(str(config_file))

        assert engine.running is False

        await engine.start()
        assert engine.running is True
        assert engine.startup_time is not None

        await engine.stop()
        assert engine.running is False

    @pytest.mark.asyncio
    async def test_core_engine_api_analyze_binary(self, config_file: Path, sample_binary: Path) -> None:
        """CoreEngine processes binary analysis API requests."""
        engine = IntellicrackcoreEngine(str(config_file))
        await engine.start()

        try:
            request = {
                "binary_path": str(sample_binary),
                "analysis_type": "quick_scan",
                "parameters": {},
            }

            response = await engine.process_api_request("analyze_binary", request)

            assert response["success"] is True
            assert "result" in response
            assert "analysis_id" in response["result"]

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_api_get_system_status(self, config_file: Path) -> None:
        """CoreEngine provides system status via API."""
        engine = IntellicrackcoreEngine(str(config_file))
        await engine.start()

        try:
            response = await engine.process_api_request("get_system_status", {})

            assert response["success"] is True
            result = response["result"]

            assert result["engine_status"] == "running"
            assert "plugin_stats" in result
            assert "resource_stats" in result
            assert "event_stats" in result

        finally:
            await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_api_invalid_method(self, config_file: Path) -> None:
        """CoreEngine rejects invalid API methods."""
        engine = IntellicrackcoreEngine(str(config_file))
        await engine.start()

        try:
            response = await engine.process_api_request("invalid_method", {})

            assert response["success"] is False
            assert "error" in response

        finally:
            await engine.stop()


class TestPluginManager:
    """Test PluginManager for plugin lifecycle management."""

    @pytest.mark.asyncio
    async def test_plugin_manager_discovers_python_modules(
        self,
        temp_plugin_dir: Path,
    ) -> None:
        """PluginManager discovers Python plugin modules."""
        test_plugin = temp_plugin_dir / "license_bypass.py"
        test_plugin.write_text(
            '''"""License bypass plugin.

Version: 1.0.0
Author: Test
"""

class Plugin:
    pass
''',
        )

        logger = logging.getLogger("test")
        event_bus = EventBus()
        config = {"directories": [str(temp_plugin_dir)], "auto_discover": True}

        manager = PluginManager(config, event_bus, logger)
        discovered = await manager.discover_plugins()

        assert len(discovered) > 0


class TestWorkflowEngine:
    """Test WorkflowEngine for workflow orchestration."""

    @pytest.mark.asyncio
    async def test_workflow_engine_registers_workflows(self) -> None:
        """WorkflowEngine registers workflow definitions."""
        logger = logging.getLogger("test")
        event_bus = EventBus()
        plugin_manager = PluginManager({}, event_bus, logger)
        engine = WorkflowEngine(plugin_manager, event_bus, logger)

        workflow = WorkflowDefinition(
            workflow_id="test_bypass",
            name="Test Bypass Workflow",
            description="Test workflow",
            steps=[
                WorkflowStep(
                    step_id="step1",
                    name="Step 1",
                    plugin_name="test_plugin",
                    method="test_method",
                ),
            ],
        )

        engine.register_workflow(workflow)

        assert "test_bypass" in engine.workflows


class TestAnalysisCoordinator:
    """Test AnalysisCoordinator for binary analysis coordination."""

    @pytest.mark.asyncio
    async def test_analysis_coordinator_queues_analysis(
        self,
        sample_binary: Path,
    ) -> None:
        """AnalysisCoordinator queues binary analysis requests."""
        logger = logging.getLogger("test")
        event_bus = EventBus()
        plugin_manager = PluginManager({}, event_bus, logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, logger)
        coordinator = AnalysisCoordinator(plugin_manager, workflow_engine, event_bus, logger)

        await coordinator.start()

        analysis_id = await coordinator.analyze_binary(
            str(sample_binary),
            analysis_type="deep_analysis",
        )

        assert analysis_id is not None
        assert analysis_id in coordinator.active_analyses

        await coordinator.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_rejects_nonexistent_file(self) -> None:
        """AnalysisCoordinator rejects nonexistent binary files."""
        logger = logging.getLogger("test")
        event_bus = EventBus()
        plugin_manager = PluginManager({}, event_bus, logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, logger)
        coordinator = AnalysisCoordinator(plugin_manager, workflow_engine, event_bus, logger)

        await coordinator.start()

        with pytest.raises(ValueError, match="Binary file not found"):
            await coordinator.analyze_binary("/nonexistent/file.exe")

        await coordinator.stop()


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_event_bus_queue_full_handling(self) -> None:
        """EventBus handles queue full condition gracefully."""
        event_bus = EventBus(max_queue_size=2)
        await event_bus.start()

        for i in range(5):
            await event_bus.emit(Event(event_type=f"event{i}", source="test"))

        stats = event_bus.get_stats()
        assert stats["queue_size"] <= 2

        await event_bus.stop()

    def test_config_manager_handles_corrupted_json(self, temp_config_dir: Path) -> None:
        """ConfigurationManager handles corrupted JSON files."""
        corrupt_config = temp_config_dir / "corrupt.json"
        corrupt_config.write_text("{ invalid json }")

        manager = ConfigurationManager(str(corrupt_config))

        assert manager.config is not None
        assert "logging" in manager.config


class TestPerformance:
    """Performance tests for core engine components."""

    @pytest.mark.asyncio
    async def test_event_bus_high_throughput(self) -> None:
        """EventBus handles high event throughput efficiently."""
        event_bus = EventBus(max_queue_size=10000)
        await event_bus.start()

        event_count = 0

        async def counter(event: Event) -> None:
            nonlocal event_count
            event_count += 1

        event_bus.subscribe("perf_test", counter)

        start_time = time.time()
        for i in range(1000):
            await event_bus.emit(Event(event_type="perf_test", source="test", data={"index": i}))

        await asyncio.sleep(1.0)
        duration = time.time() - start_time

        assert event_count > 0
        assert duration < 5.0

        await event_bus.stop()
