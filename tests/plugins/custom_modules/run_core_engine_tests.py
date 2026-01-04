"""Standalone test runner for core engine tests."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from intellicrack.plugins.custom_modules.intellicrack_core_engine import (
        EventBus,
        Event,
        EventPriority,
        IntellicrackcoreEngine,
        PluginManager,
        WorkflowEngine,
        AnalysisCoordinator,
        ResourceManager,
        ConfigurationManager,
        LoggingManager,
        JSONFormatter,
    )
    print("✓ Core engine imports successful")
except ImportError as e:
    print(f"✗ Failed to import core engine: {e}")
    sys.exit(1)


async def test_event_bus_basic() -> None:
    """Test basic EventBus functionality."""
    print("\nTest: EventBus basic operations")

    bus = EventBus()
    received: list[Event] = []

    async def handler(event: Event) -> None:
        received.append(event)

    bus.subscribe("test", handler)
    await bus.start()

    event = Event(event_type="test", source="runner", data={"msg": "hello"})
    await bus.emit(event)
    await asyncio.sleep(0.3)

    await bus.stop()

    assert len(received) == 1, f"Expected 1 event, got {len(received)}"
    assert received[0].data["msg"] == "hello"
    print("✓ EventBus delivers events to subscribers")


async def test_plugin_manager_discovery(tmp_path: Path) -> None:
    """Test plugin discovery."""
    print("\nTest: PluginManager discovery")

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()

    test_plugin = plugin_dir / "test.py"
    test_plugin.write_text('''
"""Test plugin.
@description: Test
@version: 1.0.0
"""
class TestPlugin:
    pass
''')

    import logging
    logger = logging.getLogger("test")
    bus = EventBus()

    config = {"directories": [str(plugin_dir)], "auto_discover": True}
    manager = PluginManager(config, bus, logger)

    discovered = await manager.discover_plugins()

    assert len(discovered) > 0, "Should discover at least one plugin"
    print(f"✓ Discovered {len(discovered)} plugin(s)")


async def test_core_engine_initialization(tmp_path: Path) -> None:
    """Test core engine initialization."""
    print("\nTest: Core engine initialization")

    config_file = tmp_path / "config.json"
    import json
    config = {
        "logging": {
            "console_level": "INFO",
            "file_level": "DEBUG",
            "log_directory": str(tmp_path / "logs"),
        },
        "plugins": {
            "directories": [str(tmp_path / "plugins")],
            "auto_discover": False,
        },
        "engine": {
            "max_workers": 2,
            "enable_monitoring": False,
        },
    }
    config_file.write_text(json.dumps(config))

    engine = IntellicrackcoreEngine(str(config_file))

    assert engine.config_manager is not None
    assert engine.event_bus is not None
    assert engine.plugin_manager is not None
    assert engine.workflow_engine is not None
    assert engine.analysis_coordinator is not None

    print("✓ Core engine initialized all components")


async def test_core_engine_start_stop(tmp_path: Path) -> None:
    """Test core engine start/stop."""
    print("\nTest: Core engine start/stop")

    config_file = tmp_path / "config.json"
    import json
    config = {
        "logging": {
            "console_level": "ERROR",
            "log_directory": str(tmp_path / "logs"),
        },
        "plugins": {
            "directories": [],
            "auto_discover": False,
        },
        "engine": {
            "max_workers": 2,
            "enable_monitoring": False,
        },
    }
    config_file.write_text(json.dumps(config))

    engine = IntellicrackcoreEngine(str(config_file))

    await engine.start()
    assert engine.running, "Engine should be running"
    assert engine.startup_time is not None

    await engine.stop()
    assert not engine.running, "Engine should be stopped"

    print("✓ Core engine starts and stops successfully")  # type: ignore[unreachable]


async def test_workflow_registration() -> None:
    """Test workflow registration."""
    print("\nTest: Workflow registration")

    from intellicrack.plugins.custom_modules.intellicrack_core_engine import (
        WorkflowDefinition,
        WorkflowStep,
    )

    import logging
    logger = logging.getLogger("test")
    bus = EventBus()
    plugin_manager = PluginManager({}, bus, logger)
    engine = WorkflowEngine(plugin_manager, bus, logger)

    workflow = WorkflowDefinition(
        workflow_id="test_wf",
        name="Test Workflow",
        description="Testing",
        steps=[
            WorkflowStep(
                step_id="step1",
                name="Step 1",
                plugin_name="test",
                method="test_method",
            )
        ],
    )

    engine.register_workflow(workflow)

    assert "test_wf" in engine.workflows
    print("✓ Workflow registered successfully")


async def test_json_formatter() -> None:
    """Test JSON log formatting."""
    print("\nTest: JSON formatter")

    import logging
    import json

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
    print("✓ JSON formatter produces valid JSON")


async def main() -> None:
    """Run all tests."""
    print("=" * 60)
    print("Running Core Engine Tests")
    print("=" * 60)

    import tempfile
    import shutil

    tmp_dir = Path(tempfile.mkdtemp(prefix="core_engine_test_"))

    try:
        await test_event_bus_basic()
        await test_plugin_manager_discovery(tmp_dir)
        await test_core_engine_initialization(tmp_dir)
        await test_core_engine_start_stop(tmp_dir)
        await test_workflow_registration()
        await test_json_formatter()

        print("\n" + "=" * 60)
        print("All tests PASSED")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n✗ Test FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
