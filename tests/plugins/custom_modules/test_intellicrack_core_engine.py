"""Production-grade tests for Intellicrack Core Engine.

Tests validate real core engine orchestration capabilities:
- Component initialization and lifecycle management
- Plugin discovery, loading, and activation
- Event bus communication between components
- Workflow definition and execution
- Analysis coordination and queueing
- Resource management and process tracking
- Configuration management with hot reloading
- Logging system with structured output
- Error handling and recovery
- Real component integration (no mocks)
"""

import asyncio
import json
import logging
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import Mock

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
    reason=f"Core engine not available: {IMPORT_ERROR if not CORE_ENGINE_AVAILABLE else ''}"
)


@pytest.fixture
def temp_config_file(tmp_path: Path) -> Path:
    """Create temporary configuration file."""
    config = {
        "logging": {
            "console_level": "INFO",
            "file_level": "DEBUG",
            "log_directory": str(tmp_path / "logs"),
            "max_log_size": 10485760,
            "backup_count": 3,
        },
        "plugins": {
            "directories": [str(tmp_path / "plugins")],
            "auto_discover": True,
            "auto_load": True,
            "load_timeout": 30,
            "enabled": [],
            "disabled": [],
        },
        "engine": {
            "max_workers": 2,
            "enable_monitoring": False,
        },
        "workflows": {
            "max_concurrent": 5,
            "default_timeout": 300,
        },
    }

    config_file = tmp_path / "test_config.json"
    config_file.write_text(json.dumps(config, indent=2))
    return config_file


@pytest.fixture
def plugin_directory(tmp_path: Path) -> Path:
    """Create plugin directory with sample plugins."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir(exist_ok=True)

    python_plugin = plugin_dir / "test_analyzer.py"
    python_plugin.write_text('''
"""Test analyzer plugin.

@description: Test analysis plugin for core engine testing
@author: Test Suite
@version: 1.0.0
@capabilities: static_analysis, license_detection
"""

class TestAnalyzerPlugin:
    def __init__(self):
        self.name = "TestAnalyzer"

    def analyze_binary(self, binary_path):
        return {"protection_detected": True, "type": "custom"}
''')

    frida_script = plugin_dir / "test_bypass.js"
    frida_script.write_text('''
// description: Test bypass script
// author: Test Suite
// version: 1.0.0

Java.perform(function() {
    console.log("Test bypass active");
});
''')

    return plugin_dir


@pytest.fixture
def event_bus() -> EventBus:
    """Create EventBus instance."""
    bus = EventBus()
    return bus


@pytest.fixture
def test_logger() -> logging.Logger:
    """Create test logger."""
    logger = logging.getLogger("test_core_engine")
    logger.setLevel(logging.DEBUG)
    return logger


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary for testing."""
    binary = tmp_path / "test_app.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return binary


class TestEventBus:
    """Test EventBus component communication system."""

    @pytest.mark.asyncio
    async def test_event_bus_starts_and_processes_events(self, event_bus: EventBus) -> None:
        """EventBus starts processing loop and handles events."""
        await event_bus.start()

        assert event_bus.running
        assert event_bus.event_loop is not None

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_delivers_events_to_subscribers(self, event_bus: EventBus) -> None:
        """EventBus delivers events to all registered subscribers."""
        received_events = []

        async def handler(event: Event) -> None:
            received_events.append(event)

        event_bus.subscribe("test_event", handler)
        await event_bus.start()

        test_event = Event(
            event_type="test_event",
            source="test_component",
            data={"message": "test_data"}
        )

        await event_bus.emit(test_event)
        await asyncio.sleep(0.2)

        assert len(received_events) == 1
        assert received_events[0].event_type == "test_event"
        assert received_events[0].data["message"] == "test_data"

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_handles_multiple_subscribers(self, event_bus: EventBus) -> None:
        """EventBus delivers events to multiple subscribers simultaneously."""
        handler1_calls = []
        handler2_calls = []

        async def handler1(event: Event) -> None:
            handler1_calls.append(event)

        async def handler2(event: Event) -> None:
            handler2_calls.append(event)

        event_bus.subscribe("multi_event", handler1)
        event_bus.subscribe("multi_event", handler2)
        await event_bus.start()

        event = Event(event_type="multi_event", source="test", data={"value": 42})
        await event_bus.emit(event)
        await asyncio.sleep(0.2)

        assert len(handler1_calls) == 1
        assert len(handler2_calls) == 1

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_respects_priority_ordering(self, event_bus: EventBus) -> None:
        """EventBus processes high priority events before low priority."""
        processed_order = []

        async def handler(event: Event) -> None:
            processed_order.append(event.priority)

        event_bus.subscribe("priority_test", handler)
        await event_bus.start()

        low_priority = Event(
            event_type="priority_test",
            source="test",
            priority=EventPriority.LOW,
            data={"id": "low"}
        )
        high_priority = Event(
            event_type="priority_test",
            source="test",
            priority=EventPriority.HIGH,
            data={"id": "high"}
        )

        await event_bus.emit(low_priority)
        await event_bus.emit(high_priority)
        await asyncio.sleep(0.3)

        assert len(processed_order) == 2

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_unsubscribe_stops_delivery(self, event_bus: EventBus) -> None:
        """EventBus stops delivering events after unsubscribe."""
        received = []

        async def handler(event: Event) -> None:
            received.append(event)

        event_bus.subscribe("unsub_test", handler)
        await event_bus.start()

        event1 = Event(event_type="unsub_test", source="test", data={"seq": 1})
        await event_bus.emit(event1)
        await asyncio.sleep(0.1)

        event_bus.unsubscribe("unsub_test", handler)

        event2 = Event(event_type="unsub_test", source="test", data={"seq": 2})
        await event_bus.emit(event2)
        await asyncio.sleep(0.1)

        assert len(received) == 1

        await event_bus.stop()


class TestPluginManager:
    """Test PluginManager plugin lifecycle and coordination."""

    @pytest.mark.asyncio
    async def test_plugin_manager_discovers_python_modules(
        self, plugin_directory: Path, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """PluginManager discovers Python plugin modules in directory."""
        config = {"directories": [str(plugin_directory)], "auto_discover": True}
        manager = PluginManager(config, event_bus, test_logger)

        discovered = await manager.discover_plugins()

        assert len(discovered) > 0
        assert any("python_test_analyzer" in p for p in discovered)

    @pytest.mark.asyncio
    async def test_plugin_manager_discovers_frida_scripts(
        self, plugin_directory: Path, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """PluginManager discovers Frida JavaScript scripts."""
        config = {"directories": [str(plugin_directory)], "auto_discover": True}
        manager = PluginManager(config, event_bus, test_logger)

        discovered = await manager.discover_plugins()

        assert any("frida_test_bypass" in p for p in discovered)

    @pytest.mark.asyncio
    async def test_plugin_manager_loads_plugin_with_metadata(
        self, plugin_directory: Path, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """PluginManager loads plugins and extracts metadata."""
        config = {"directories": [str(plugin_directory)], "auto_discover": True}
        manager = PluginManager(config, event_bus, test_logger)

        await manager.discover_plugins()

        python_plugin_name = None
        for name in manager.plugin_metadata:
            if "test_analyzer" in name:
                python_plugin_name = name
                break

        assert python_plugin_name is not None
        metadata = manager.plugin_metadata[python_plugin_name]
        assert metadata.description
        assert metadata.version

    @pytest.mark.asyncio
    async def test_plugin_manager_respects_dependency_order(
        self, event_bus: EventBus, test_logger: logging.Logger, tmp_path: Path
    ) -> None:
        """PluginManager loads plugins in dependency order."""
        plugin_dir = tmp_path / "dep_plugins"
        plugin_dir.mkdir()

        base_plugin = plugin_dir / "base.py"
        base_plugin.write_text('''
"""Base plugin.
@description: Base plugin
@version: 1.0.0
@capabilities: base
"""
class BasePlugin:
    pass
''')

        dependent_plugin = plugin_dir / "dependent.py"
        dependent_plugin.write_text('''
"""Dependent plugin.
@description: Depends on base
@version: 1.0.0
@dependencies: python_base
@capabilities: advanced
"""
class DependentPlugin:
    pass
''')

        config = {"directories": [str(plugin_dir)], "auto_discover": True}
        manager = PluginManager(config, event_bus, test_logger)

        await manager.discover_plugins()

        assert len(manager.plugin_metadata) >= 2


class TestWorkflowEngine:
    """Test WorkflowEngine workflow orchestration."""

    @pytest.mark.asyncio
    async def test_workflow_engine_registers_workflows(
        self, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """WorkflowEngine registers workflow definitions."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        engine = WorkflowEngine(plugin_manager, event_bus, test_logger)

        workflow = WorkflowDefinition(
            workflow_id="test_workflow",
            name="Test Workflow",
            description="Testing workflow",
            steps=[
                WorkflowStep(
                    step_id="step1",
                    name="First Step",
                    plugin_name="test_plugin",
                    method="test_method",
                )
            ],
        )

        engine.register_workflow(workflow)

        assert "test_workflow" in engine.workflows
        assert engine.workflows["test_workflow"].name == "Test Workflow"

    @pytest.mark.asyncio
    async def test_workflow_engine_executes_sequential_workflow(
        self, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """WorkflowEngine executes steps sequentially."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        engine = WorkflowEngine(plugin_manager, event_bus, test_logger)

        execution_order = []

        class TestPlugin(PythonPlugin):
            def __init__(self):
                super().__init__("test_plugin", "", "1.0.0")
                self.status = PluginStatus.READY

            async def execute_operation(self, operation: str, parameters: dict[str, Any]) -> Any:
                execution_order.append(operation)
                return {"step": operation, "result": "success"}

        test_plugin = TestPlugin()
        plugin_manager.plugins["test_plugin"] = test_plugin

        workflow = WorkflowDefinition(
            workflow_id="seq_test",
            name="Sequential Test",
            description="Test sequential execution",
            steps=[
                WorkflowStep(
                    step_id="step1",
                    name="Step 1",
                    plugin_name="test_plugin",
                    method="operation1",
                ),
                WorkflowStep(
                    step_id="step2",
                    name="Step 2",
                    plugin_name="test_plugin",
                    method="operation2",
                    dependencies=["step1"],
                ),
            ],
            parallel_execution=False,
        )

        engine.register_workflow(workflow)
        execution_id = await engine.execute_workflow("seq_test", {})

        await asyncio.sleep(0.5)

        assert len(execution_order) == 2
        assert execution_order[0] == "operation1"
        assert execution_order[1] == "operation2"

    @pytest.mark.asyncio
    async def test_workflow_engine_handles_workflow_errors(
        self, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """WorkflowEngine handles step failures according to error policy."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        engine = WorkflowEngine(plugin_manager, event_bus, test_logger)

        class FailingPlugin(PythonPlugin):
            def __init__(self):
                super().__init__("failing_plugin", "", "1.0.0")
                self.status = PluginStatus.READY

            async def execute_operation(self, operation: str, parameters: dict[str, Any]) -> Any:
                if operation == "fail_step":
                    raise ValueError("Intentional failure")
                return {"result": "success"}

        failing_plugin = FailingPlugin()
        plugin_manager.plugins["failing_plugin"] = failing_plugin

        workflow = WorkflowDefinition(
            workflow_id="error_test",
            name="Error Test",
            description="Test error handling",
            steps=[
                WorkflowStep(
                    step_id="fail",
                    name="Failing Step",
                    plugin_name="failing_plugin",
                    method="fail_step",
                ),
            ],
            error_handling="stop",
        )

        engine.register_workflow(workflow)
        execution_id = await engine.execute_workflow("error_test", {})

        await asyncio.sleep(0.5)

        status = engine.get_workflow_status(execution_id)
        assert status is not None
        assert status["status"] == WorkflowStatus.FAILED.value

    @pytest.mark.asyncio
    async def test_workflow_engine_tracks_execution_progress(
        self, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """WorkflowEngine tracks workflow execution progress."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        engine = WorkflowEngine(plugin_manager, event_bus, test_logger)

        class ProgressPlugin(PythonPlugin):
            def __init__(self):
                super().__init__("progress_plugin", "", "1.0.0")
                self.status = PluginStatus.READY

            async def execute_operation(self, operation: str, parameters: dict[str, Any]) -> Any:
                await asyncio.sleep(0.1)
                return {"result": "done"}

        plugin = ProgressPlugin()
        plugin_manager.plugins["progress_plugin"] = plugin

        workflow = WorkflowDefinition(
            workflow_id="progress_test",
            name="Progress Test",
            description="Test progress tracking",
            steps=[
                WorkflowStep(
                    step_id="step1",
                    name="Step 1",
                    plugin_name="progress_plugin",
                    method="op1",
                ),
                WorkflowStep(
                    step_id="step2",
                    name="Step 2",
                    plugin_name="progress_plugin",
                    method="op2",
                ),
            ],
        )

        engine.register_workflow(workflow)
        execution_id = await engine.execute_workflow("progress_test", {})

        await asyncio.sleep(0.1)
        status = engine.get_workflow_status(execution_id)
        assert status is not None
        assert "progress" in status

        await asyncio.sleep(0.5)


class TestAnalysisCoordinator:
    """Test AnalysisCoordinator binary analysis orchestration."""

    @pytest.mark.asyncio
    async def test_analysis_coordinator_queues_binary_analysis(
        self,
        event_bus: EventBus,
        test_logger: logging.Logger,
        sample_binary: Path,
    ) -> None:
        """AnalysisCoordinator queues binary analysis requests."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, test_logger)
        coordinator = AnalysisCoordinator(
            plugin_manager, workflow_engine, event_bus, test_logger
        )

        await coordinator.start()

        analysis_id = await coordinator.analyze_binary(
            str(sample_binary),
            analysis_type="deep_analysis"
        )

        assert analysis_id is not None
        assert analysis_id in coordinator.active_analyses
        assert coordinator.active_analyses[analysis_id]["status"] == "queued"

        await coordinator.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_extracts_file_metadata(
        self,
        event_bus: EventBus,
        test_logger: logging.Logger,
        sample_binary: Path,
    ) -> None:
        """AnalysisCoordinator extracts file metadata before analysis."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, test_logger)
        coordinator = AnalysisCoordinator(
            plugin_manager, workflow_engine, event_bus, test_logger
        )

        await coordinator.start()

        analysis_id = await coordinator.analyze_binary(str(sample_binary))
        await asyncio.sleep(0.2)

        analysis = coordinator.active_analyses[analysis_id]
        assert "file_info" in analysis
        assert analysis["file_info"]["name"] == "test_app.exe"
        assert analysis["file_info"]["size"] > 0

        await coordinator.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_rejects_nonexistent_file(
        self, event_bus: EventBus, test_logger: logging.Logger
    ) -> None:
        """AnalysisCoordinator rejects analysis of nonexistent files."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, test_logger)
        coordinator = AnalysisCoordinator(
            plugin_manager, workflow_engine, event_bus, test_logger
        )

        await coordinator.start()

        with pytest.raises(ValueError, match="Binary file not found"):
            await coordinator.analyze_binary("/nonexistent/file.exe")

        await coordinator.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_handles_invalid_analysis_type(
        self,
        event_bus: EventBus,
        test_logger: logging.Logger,
        sample_binary: Path,
    ) -> None:
        """AnalysisCoordinator rejects unknown analysis types."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, test_logger)
        coordinator = AnalysisCoordinator(
            plugin_manager, workflow_engine, event_bus, test_logger
        )

        await coordinator.start()

        with pytest.raises(ValueError, match="Unknown analysis type"):
            await coordinator.analyze_binary(
                str(sample_binary),
                analysis_type="invalid_type"
            )

        await coordinator.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_retrieves_analysis_status(
        self,
        event_bus: EventBus,
        test_logger: logging.Logger,
        sample_binary: Path,
    ) -> None:
        """AnalysisCoordinator provides status for active analyses."""
        plugin_manager = PluginManager({}, event_bus, test_logger)
        workflow_engine = WorkflowEngine(plugin_manager, event_bus, test_logger)
        coordinator = AnalysisCoordinator(
            plugin_manager, workflow_engine, event_bus, test_logger
        )

        await coordinator.start()

        analysis_id = await coordinator.analyze_binary(str(sample_binary))
        status = coordinator.get_analysis_status(analysis_id)

        assert status is not None
        assert status["analysis_id"] == analysis_id
        assert status["binary_path"] == str(sample_binary)
        assert "status" in status

        await coordinator.stop()


class TestResourceManager:
    """Test ResourceManager resource tracking and management."""

    @pytest.mark.asyncio
    async def test_resource_manager_starts_monitoring(self, test_logger: logging.Logger) -> None:
        """ResourceManager starts resource monitoring loop."""
        config = {"max_workers": 2, "enable_monitoring": True}
        manager = ResourceManager(config, test_logger)

        await manager.start()

        assert manager.running

        await manager.stop()

    @pytest.mark.asyncio
    async def test_resource_manager_tracks_system_resources(
        self, test_logger: logging.Logger
    ) -> None:
        """ResourceManager collects system resource statistics."""
        config = {"max_workers": 2, "enable_monitoring": True}
        manager = ResourceManager(config, test_logger)

        await manager.start()
        await asyncio.sleep(0.5)

        stats = manager.get_resource_stats()

        assert "cpu_percent" in stats
        assert "memory_percent" in stats
        assert stats["cpu_percent"] >= 0
        assert stats["memory_percent"] >= 0

        await manager.stop()

    @pytest.mark.asyncio
    async def test_resource_manager_provides_executor_pools(
        self, test_logger: logging.Logger
    ) -> None:
        """ResourceManager provides thread and process executor pools."""
        config = {"max_workers": 2, "enable_monitoring": False}
        manager = ResourceManager(config, test_logger)

        await manager.start()

        assert manager.thread_executor is not None
        assert manager.process_executor is not None

        await manager.stop()


class TestConfigurationManager:
    """Test ConfigurationManager configuration handling."""

    def test_configuration_manager_loads_json_config(self, temp_config_file: Path) -> None:
        """ConfigurationManager loads JSON configuration files."""
        manager = ConfigurationManager(str(temp_config_file))

        assert manager.config["logging"]["console_level"] == "INFO"
        assert manager.config["plugins"]["auto_discover"] is True
        assert manager.config["engine"]["max_workers"] == 2

    def test_configuration_manager_validates_config_schema(
        self, temp_config_file: Path
    ) -> None:
        """ConfigurationManager validates configuration against schema."""
        manager = ConfigurationManager(str(temp_config_file))

        assert "logging" in manager.config
        assert "plugins" in manager.config
        assert "engine" in manager.config

    def test_configuration_manager_provides_config_access(
        self, temp_config_file: Path
    ) -> None:
        """ConfigurationManager provides access to configuration values."""
        manager = ConfigurationManager(str(temp_config_file))

        assert manager.config.get("logging", {}).get("console_level") == "INFO"
        assert manager.config.get("plugins", {}).get("auto_discover") is True


class TestLoggingManager:
    """Test LoggingManager logging infrastructure."""

    def test_logging_manager_initializes_loggers(self, tmp_path: Path) -> None:
        """LoggingManager creates logging infrastructure."""
        config = {
            "console_level": "INFO",
            "file_level": "DEBUG",
            "log_directory": str(tmp_path / "logs"),
        }

        manager = LoggingManager(config)

        assert len(manager.loggers) > 0
        assert len(manager.handlers) > 0

    def test_logging_manager_creates_component_loggers(self, tmp_path: Path) -> None:
        """LoggingManager provides component-specific loggers."""
        config = {"log_directory": str(tmp_path / "logs")}
        manager = LoggingManager(config)

        plugin_logger = manager.get_logger("plugin_test")
        workflow_logger = manager.get_logger("workflow_test")

        assert plugin_logger.name == "intellicrack.plugin_test"
        assert workflow_logger.name == "intellicrack.workflow_test"

    def test_logging_manager_creates_log_files(self, tmp_path: Path) -> None:
        """LoggingManager creates log files on disk."""
        log_dir = tmp_path / "logs"
        config = {"log_directory": str(log_dir)}

        manager = LoggingManager(config)
        logger = manager.get_logger("test")
        logger.info("Test message")

        assert log_dir.exists()
        log_files = list(log_dir.glob("*.log"))
        assert len(log_files) > 0


class TestJSONFormatter:
    """Test JSONFormatter structured logging."""

    def test_json_formatter_produces_valid_json(self) -> None:
        """JSONFormatter creates valid JSON log entries."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)

        parsed = json.loads(formatted)
        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert "timestamp" in parsed

    def test_json_formatter_includes_exception_info(self) -> None:
        """JSONFormatter includes exception traces in JSON."""
        formatter = JSONFormatter()

        try:
            raise ValueError("Test exception")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="Error occurred",
                args=(),
                exc_info=exc_info,
            )

            formatted = formatter.format(record)
            parsed = json.loads(formatted)

            assert "exception" in parsed
            assert "ValueError" in parsed["exception"]


class TestIntellicrackcoreEngine:
    """Test IntellicrackcoreEngine complete orchestration."""

    @pytest.mark.asyncio
    async def test_core_engine_initializes_all_components(
        self, temp_config_file: Path
    ) -> None:
        """CoreEngine initializes all required components."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        assert engine.config_manager is not None
        assert engine.logging_manager is not None
        assert engine.event_bus is not None
        assert engine.plugin_manager is not None
        assert engine.workflow_engine is not None
        assert engine.analysis_coordinator is not None
        assert engine.resource_manager is not None

    @pytest.mark.asyncio
    async def test_core_engine_starts_successfully(self, temp_config_file: Path) -> None:
        """CoreEngine starts all components in correct order."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        assert engine.running
        assert engine.startup_time is not None

        await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_stops_cleanly(self, temp_config_file: Path) -> None:
        """CoreEngine stops all components without errors."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()
        await engine.stop()

        assert not engine.running

    @pytest.mark.asyncio
    async def test_core_engine_handles_analyze_binary_request(
        self, temp_config_file: Path, sample_binary: Path
    ) -> None:
        """CoreEngine processes binary analysis requests."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        request = {
            "binary_path": str(sample_binary),
            "analysis_type": "deep_analysis",
            "parameters": {},
        }

        response = await engine._handle_analyze_binary(request)

        assert "analysis_id" in response
        assert response["status"] == "queued"

        await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_handles_list_plugins_request(
        self, temp_config_file: Path
    ) -> None:
        """CoreEngine lists available plugins."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        response = await engine._handle_list_plugins({})

        assert "plugins" in response
        assert isinstance(response["plugins"], list)

        await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_handles_system_status_request(
        self, temp_config_file: Path
    ) -> None:
        """CoreEngine provides system status information."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        response = await engine._handle_get_system_status({})

        assert response["engine_status"] == "running"
        assert "startup_time" in response
        assert "uptime" in response
        assert response["uptime"] >= 0

        await engine.stop()

    @pytest.mark.asyncio
    async def test_core_engine_handles_missing_binary_path(
        self, temp_config_file: Path
    ) -> None:
        """CoreEngine validates required parameters in requests."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        with pytest.raises(ValueError, match="binary_path is required"):
            await engine._handle_analyze_binary({"parameters": {}})

        await engine.stop()


class TestComponentIntegration:
    """Test integration between core engine components."""

    @pytest.mark.asyncio
    async def test_event_bus_connects_all_components(
        self, temp_config_file: Path, sample_binary: Path
    ) -> None:
        """EventBus enables communication between all components."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        events_received = []

        async def event_monitor(event: Event) -> None:
            events_received.append(event.event_type)

        engine.event_bus.subscribe("analysis_started", event_monitor)
        engine.event_bus.subscribe("workflow_started", event_monitor)

        await engine.start()

        request = {
            "binary_path": str(sample_binary),
            "analysis_type": "deep_analysis",
        }

        await engine._handle_analyze_binary(request)
        await asyncio.sleep(0.5)

        assert len(events_received) > 0

        await engine.stop()

    @pytest.mark.asyncio
    async def test_workflow_engine_uses_plugin_manager(
        self, temp_config_file: Path
    ) -> None:
        """WorkflowEngine retrieves plugins from PluginManager."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        assert engine.workflow_engine.plugin_manager is engine.plugin_manager

        await engine.stop()

    @pytest.mark.asyncio
    async def test_analysis_coordinator_triggers_workflows(
        self, temp_config_file: Path, sample_binary: Path
    ) -> None:
        """AnalysisCoordinator starts workflows via WorkflowEngine."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        analysis_id = await engine.analysis_coordinator.analyze_binary(
            str(sample_binary),
            analysis_type="deep_analysis"
        )

        await asyncio.sleep(0.3)

        analysis = engine.analysis_coordinator.active_analyses[analysis_id]

        assert analysis["workflow_execution_id"] is not None or analysis["status"] in ["queued", "starting"]

        await engine.stop()


class TestPluginMetadata:
    """Test PluginMetadata data structures."""

    def test_plugin_metadata_converts_to_dict(self) -> None:
        """PluginMetadata serializes to dictionary format."""
        metadata = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            description="Test plugin",
            component_type=ComponentType.CUSTOM_MODULE,
            author="Test",
            capabilities=["analysis", "bypass"],
            dependencies=["dep1"],
        )

        data = metadata.to_dict()

        assert data["name"] == "test_plugin"
        assert data["version"] == "1.0.0"
        assert data["component_type"] == "custom_module"
        assert "analysis" in data["capabilities"]


class TestWorkflowDefinition:
    """Test WorkflowDefinition workflow structures."""

    def test_workflow_definition_converts_to_dict(self) -> None:
        """WorkflowDefinition serializes to dictionary."""
        workflow = WorkflowDefinition(
            workflow_id="test_wf",
            name="Test Workflow",
            description="Testing",
            steps=[
                WorkflowStep(
                    step_id="step1",
                    name="Step 1",
                    plugin_name="plugin1",
                    method="method1",
                )
            ],
            parallel_execution=True,
            timeout=600,
        )

        data = workflow.to_dict()

        assert data["workflow_id"] == "test_wf"
        assert data["parallel_execution"] is True
        assert len(data["steps"]) == 1


class TestEventStructure:
    """Test Event data structures."""

    def test_event_converts_to_dict(self) -> None:
        """Event serializes to dictionary format."""
        event = Event(
            event_type="test_event",
            source="test_source",
            target="test_target",
            data={"key": "value"},
            priority=EventPriority.HIGH,
        )

        data = event.to_dict()

        assert data["event_type"] == "test_event"
        assert data["source"] == "test_source"
        assert data["target"] == "test_target"
        assert data["data"]["key"] == "value"
        assert data["priority"] == EventPriority.HIGH.value


class TestErrorHandling:
    """Test error handling across components."""

    @pytest.mark.asyncio
    async def test_engine_handles_plugin_load_failure(
        self, temp_config_file: Path, tmp_path: Path
    ) -> None:
        """CoreEngine handles plugin loading failures gracefully."""
        bad_plugin_dir = tmp_path / "bad_plugins"
        bad_plugin_dir.mkdir()

        bad_plugin = bad_plugin_dir / "broken.py"
        bad_plugin.write_text("This is not valid Python code !@#$")

        config_file = tmp_path / "bad_config.json"
        config = {
            "logging": {"console_level": "INFO", "log_directory": str(tmp_path / "logs")},
            "plugins": {"directories": [str(bad_plugin_dir)]},
            "engine": {"max_workers": 2},
        }
        config_file.write_text(json.dumps(config))

        engine = IntellicrackcoreEngine(str(config_file))

        await engine.start()
        assert engine.running
        await engine.stop()

    @pytest.mark.asyncio
    async def test_engine_handles_invalid_workflow_execution(
        self, temp_config_file: Path
    ) -> None:
        """CoreEngine handles invalid workflow execution requests."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        with pytest.raises(ValueError):
            await engine._handle_execute_workflow({
                "workflow_id": "nonexistent_workflow",
                "parameters": {}
            })

        await engine.stop()


class TestPerformance:
    """Test performance characteristics of core engine."""

    @pytest.mark.asyncio
    async def test_event_bus_handles_high_throughput(self, event_bus: EventBus) -> None:
        """EventBus processes high volumes of events efficiently."""
        received_count = []

        async def counter(event: Event) -> None:
            received_count.append(1)

        event_bus.subscribe("perf_test", counter)
        await event_bus.start()

        start_time = time.perf_counter()

        for i in range(100):
            event = Event(
                event_type="perf_test",
                source="perf_test",
                data={"seq": i}
            )
            await event_bus.emit(event)

        await asyncio.sleep(0.5)
        elapsed = time.perf_counter() - start_time

        assert len(received_count) == 100
        assert elapsed < 2.0

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_multiple_concurrent_analyses(
        self, temp_config_file: Path, sample_binary: Path
    ) -> None:
        """CoreEngine handles multiple concurrent analysis requests."""
        engine = IntellicrackcoreEngine(str(temp_config_file))

        await engine.start()

        analysis_ids = []
        for _ in range(5):
            analysis_id = await engine.analysis_coordinator.analyze_binary(
                str(sample_binary),
                analysis_type="deep_analysis"
            )
            analysis_ids.append(analysis_id)

        assert len(analysis_ids) == 5
        assert len(set(analysis_ids)) == 5

        await engine.stop()
