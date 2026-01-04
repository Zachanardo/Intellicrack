"""Production tests for Application Context Manager.

Tests validate real application state management, signal emissions,
binary/project lifecycle, plugin registration, and task tracking for
licensing analysis workflows.
"""

import json
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.app_context import AppContext, get_app_context


@pytest.fixture
def temp_binary_file(tmp_path: Path) -> Path:
    """Create temporary binary file for testing."""
    binary_file = tmp_path / "test_binary.exe"
    binary_file.write_bytes(b"\x4D\x5A" + b"\x00" * 1024)
    return binary_file


@pytest.fixture
def temp_project_file(tmp_path: Path) -> Path:
    """Create temporary project file for testing."""
    project_file = tmp_path / "test_project.icp"
    project_data: dict[str, Any] = {
        "name": "Test Project",
        "created_at": "2025-01-01T00:00:00",
        "binary_path": None,
        "analysis_results": {},
        "settings": {},
    }
    project_file.write_text(json.dumps(project_data))
    return project_file


@pytest.fixture
def app_context() -> Generator[AppContext, None, None]:
    """Provide fresh app context for each test."""
    context = AppContext()
    yield context
    context.reset_state()


class TestAppContextBinaryManagement:
    """Test binary loading and lifecycle management."""

    def test_load_binary_succeeds_with_valid_file(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Binary loads successfully and state updates correctly."""
        signal_received = False
        binary_info_received = None

        def on_binary_loaded(info: dict[str, Any]) -> None:
            nonlocal signal_received, binary_info_received
            signal_received = True
            binary_info_received = info

        if app_context.binary_loaded:
            app_context.binary_loaded.connect(on_binary_loaded)

        result = app_context.load_binary(str(temp_binary_file), {"protection": "VMProtect"})

        assert result is True

        current_binary = app_context.get_current_binary()
        assert current_binary is not None
        assert current_binary["name"] == temp_binary_file.name
        assert current_binary["size"] == temp_binary_file.stat().st_size
        assert current_binary["path"] == str(temp_binary_file.absolute())
        assert "loaded_at" in current_binary
        assert current_binary["metadata"]["protection"] == "VMProtect"

        assert str(temp_binary_file.absolute()) in app_context.get_recent_files()

    def test_load_binary_fails_with_nonexistent_file(self, app_context: AppContext) -> None:
        """Binary loading fails gracefully for nonexistent file."""
        result = app_context.load_binary("/nonexistent/binary.exe")

        assert result is False
        assert app_context.get_current_binary() is None

    def test_unload_binary_clears_state(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Unloading binary clears current binary and analysis results."""
        app_context.load_binary(str(temp_binary_file))
        app_context.set_analysis_results("protection_scan", {"protections": ["VMProtect"]})

        assert app_context.get_current_binary() is not None
        assert len(app_context.get_analysis_results()) > 0

        app_context.unload_binary()

        assert app_context.get_current_binary() is None
        assert len(app_context.get_analysis_results()) == 0

    def test_load_binary_emits_signal(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Loading binary emits binary_loaded signal with correct data."""
        signal_emitted = False
        emitted_info = None

        def signal_handler(info: dict[str, Any]) -> None:
            nonlocal signal_emitted, emitted_info
            signal_emitted = True
            emitted_info = info

        if app_context.binary_loaded:
            app_context.binary_loaded.connect(signal_handler)

        app_context.load_binary(str(temp_binary_file))

        if app_context.binary_loaded:
            assert signal_emitted
            assert emitted_info is not None
            assert emitted_info["name"] == temp_binary_file.name

    def test_unload_binary_emits_signal(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Unloading binary emits binary_unloaded signal."""
        app_context.load_binary(str(temp_binary_file))

        signal_emitted = False

        def signal_handler() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        if app_context.binary_unloaded:
            app_context.binary_unloaded.connect(signal_handler)

        app_context.unload_binary()

        if app_context.binary_unloaded:
            assert signal_emitted

    def test_recent_files_tracks_loaded_binaries(self, app_context: AppContext, tmp_path: Path) -> None:
        """Recent files list tracks loaded binaries correctly."""
        binaries = []
        for i in range(3):
            binary_file = tmp_path / f"binary_{i}.exe"
            binary_file.write_bytes(b"\x4D\x5A" + b"\x00" * 100)
            binaries.append(binary_file)

        for binary in binaries:
            app_context.load_binary(str(binary))
            app_context.unload_binary()

        recent_files = app_context.get_recent_files()

        assert len(recent_files) == 3
        assert str(binaries[2].absolute()) == recent_files[0]
        assert str(binaries[1].absolute()) == recent_files[1]
        assert str(binaries[0].absolute()) == recent_files[2]

    def test_recent_files_limited_to_ten_entries(self, app_context: AppContext, tmp_path: Path) -> None:
        """Recent files list limited to 10 most recent entries."""
        for i in range(15):
            binary_file = tmp_path / f"binary_{i}.exe"
            binary_file.write_bytes(b"\x4D\x5A" + b"\x00" * 100)
            app_context.load_binary(str(binary_file))
            app_context.unload_binary()

        recent_files = app_context.get_recent_files()

        assert len(recent_files) == 10


class TestAppContextAnalysisManagement:
    """Test analysis results storage and retrieval."""

    def test_set_analysis_results_stores_data(self, app_context: AppContext) -> None:
        """Analysis results stored correctly with timestamp."""
        results = {
            "protections": ["VMProtect", "Themida"],
            "entry_point": "0x401000",
            "packed": True,
        }

        app_context.set_analysis_results("protection_scan", results)

        stored = app_context.get_analysis_results("protection_scan")

        assert "results" in stored
        assert "timestamp" in stored
        assert stored["results"] == results
        assert stored["results"]["protections"] == ["VMProtect", "Themida"]

    def test_get_analysis_results_returns_all_when_no_type(self, app_context: AppContext) -> None:
        """Getting analysis results without type returns all results."""
        app_context.set_analysis_results("scan1", {"data": "value1"})
        app_context.set_analysis_results("scan2", {"data": "value2"})

        all_results = app_context.get_analysis_results()

        assert "scan1" in all_results
        assert "scan2" in all_results
        assert len(all_results) == 2

    def test_get_analysis_results_returns_empty_for_nonexistent_type(self, app_context: AppContext) -> None:
        """Getting nonexistent analysis type returns empty dict."""
        result = app_context.get_analysis_results("nonexistent")

        assert result == {}

    def test_set_analysis_results_emits_completion_signal(self, app_context: AppContext) -> None:
        """Setting analysis results emits analysis_completed signal."""
        signal_emitted = False
        emitted_type = None
        emitted_results = None

        def signal_handler(analysis_type: str, results: dict[str, Any]) -> None:
            nonlocal signal_emitted, emitted_type, emitted_results
            signal_emitted = True
            emitted_type = analysis_type
            emitted_results = results

        if app_context.analysis_completed:
            app_context.analysis_completed.connect(signal_handler)

        results = {"protections": ["Themida"]}
        app_context.set_analysis_results("protection_scan", results)

        if app_context.analysis_completed:
            assert signal_emitted
            assert emitted_type == "protection_scan"
            assert emitted_results == results

    def test_start_analysis_emits_signal(self, app_context: AppContext) -> None:
        """Starting analysis emits analysis_started signal."""
        signal_emitted = False
        emitted_type = None
        emitted_options = None

        def signal_handler(analysis_type: str, options: dict[str, Any]) -> None:
            nonlocal signal_emitted, emitted_type, emitted_options
            signal_emitted = True
            emitted_type = analysis_type
            emitted_options = options

        if app_context.analysis_started:
            app_context.analysis_started.connect(signal_handler)

        options = {"deep_scan": True, "timeout": 300}
        app_context.start_analysis("vulnerability_scan", options)

        if app_context.analysis_started:
            assert signal_emitted
            assert emitted_type == "vulnerability_scan"
            assert emitted_options == options

    def test_fail_analysis_emits_signal(self, app_context: AppContext) -> None:
        """Failing analysis emits analysis_failed signal."""
        signal_emitted = False
        emitted_type = None
        emitted_error = None

        def signal_handler(analysis_type: str, error: str) -> None:
            nonlocal signal_emitted, emitted_type, emitted_error
            signal_emitted = True
            emitted_type = analysis_type
            emitted_error = error

        if app_context.analysis_failed:
            app_context.analysis_failed.connect(signal_handler)

        app_context.fail_analysis("protection_scan", "Timeout exceeded")

        if app_context.analysis_failed:
            assert signal_emitted
            assert emitted_type == "protection_scan"
            assert emitted_error == "Timeout exceeded"


class TestAppContextProjectManagement:
    """Test project loading, saving, and lifecycle."""

    def test_load_project_succeeds_with_valid_file(self, app_context: AppContext, temp_project_file: Path) -> None:
        """Project loads successfully from valid JSON file."""
        result = app_context.load_project(str(temp_project_file))

        assert result is True

        project = app_context._state["current_project"]
        assert project is not None
        assert project["name"] == "Test Project"
        assert project["path"] == str(temp_project_file.absolute())
        assert "loaded_at" in project

        assert str(temp_project_file.absolute()) in app_context.get_recent_projects()

    def test_load_project_fails_with_nonexistent_file(self, app_context: AppContext) -> None:
        """Project loading fails gracefully for nonexistent file."""
        result = app_context.load_project("/nonexistent/project.icp")

        assert result is False
        assert app_context._state["current_project"] is None

    def test_load_project_fails_with_invalid_json(self, app_context: AppContext, tmp_path: Path) -> None:
        """Project loading fails gracefully for invalid JSON."""
        invalid_project = tmp_path / "invalid.icp"
        invalid_project.write_text("{ invalid json content }")

        result = app_context.load_project(str(invalid_project))

        assert result is False
        assert app_context._state["current_project"] is None

    def test_load_project_restores_analysis_results(self, app_context: AppContext, tmp_path: Path) -> None:
        """Loading project restores saved analysis results."""
        project_file = tmp_path / "project_with_results.icp"
        project_data = {
            "name": "Project With Results",
            "analysis_results": {
                "protection_scan": {
                    "results": {"protections": ["VMProtect"]},
                    "timestamp": "2025-01-01T00:00:00",
                }
            },
        }
        project_file.write_text(json.dumps(project_data))

        app_context.load_project(str(project_file))

        results = app_context.get_analysis_results("protection_scan")
        assert results["results"]["protections"] == ["VMProtect"]

    def test_load_project_loads_associated_binary(self, app_context: AppContext, tmp_path: Path, temp_binary_file: Path) -> None:
        """Loading project with binary_path loads the binary."""
        project_file = tmp_path / "project_with_binary.icp"
        project_data = {
            "name": "Project With Binary",
            "binary_path": str(temp_binary_file),
        }
        project_file.write_text(json.dumps(project_data))

        app_context.load_project(str(project_file))

        current_binary = app_context.get_current_binary()
        assert current_binary is not None
        assert current_binary["name"] == temp_binary_file.name

    def test_save_project_creates_valid_json_file(self, app_context: AppContext, tmp_path: Path, temp_binary_file: Path) -> None:
        """Saving project creates valid JSON file with current state."""
        app_context.load_binary(str(temp_binary_file))
        app_context.set_analysis_results("scan1", {"data": "value"})

        project_path = tmp_path / "saved_project.icp"
        result = app_context.save_project(str(project_path))

        assert result is True
        assert project_path.exists()

        with open(project_path) as f:
            saved_data = json.load(f)

        assert saved_data["name"] == "saved_project"
        assert saved_data["binary_path"] == str(temp_binary_file.absolute())
        assert "scan1" in saved_data["analysis_results"]
        assert "created_at" in saved_data

    def test_save_project_creates_parent_directory(self, app_context: AppContext, tmp_path: Path) -> None:
        """Saving project creates parent directories if needed."""
        project_path = tmp_path / "nested" / "directories" / "project.icp"

        result = app_context.save_project(str(project_path))

        assert result is True
        assert project_path.exists()
        assert project_path.parent.exists()

    def test_close_project_clears_state(self, app_context: AppContext, temp_project_file: Path) -> None:
        """Closing project clears current project state."""
        app_context.load_project(str(temp_project_file))

        assert app_context._state["current_project"] is not None

        app_context.close_project()

        assert app_context._state["current_project"] is None

    def test_load_project_emits_signal(self, app_context: AppContext, temp_project_file: Path) -> None:
        """Loading project emits project_loaded signal."""
        signal_emitted = False
        emitted_info = None

        def signal_handler(info: dict[str, Any]) -> None:
            nonlocal signal_emitted, emitted_info
            signal_emitted = True
            emitted_info = info

        if app_context.project_loaded:
            app_context.project_loaded.connect(signal_handler)

        app_context.load_project(str(temp_project_file))

        if app_context.project_loaded:
            assert signal_emitted
            assert emitted_info is not None
            assert emitted_info["name"] == "Test Project"

    def test_save_project_emits_signal(self, app_context: AppContext, tmp_path: Path) -> None:
        """Saving project emits project_saved signal."""
        signal_emitted = False
        emitted_path = None

        def signal_handler(path: str) -> None:
            nonlocal signal_emitted, emitted_path
            signal_emitted = True
            emitted_path = path

        if app_context.project_saved:
            app_context.project_saved.connect(signal_handler)

        project_path = tmp_path / "test.icp"
        app_context.save_project(str(project_path))

        if app_context.project_saved:
            assert signal_emitted
            assert emitted_path == str(project_path.absolute())

    def test_close_project_emits_signal(self, app_context: AppContext, temp_project_file: Path) -> None:
        """Closing project emits project_closed signal."""
        app_context.load_project(str(temp_project_file))

        signal_emitted = False

        def signal_handler() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        if app_context.project_closed:
            app_context.project_closed.connect(signal_handler)

        app_context.close_project()

        if app_context.project_closed:
            assert signal_emitted


class TestAppContextPluginManagement:
    """Test plugin registration and lifecycle."""

    def test_register_plugin_adds_to_loaded_plugins(self, app_context: AppContext) -> None:
        """Registering plugin adds it to loaded plugins registry."""
        plugin_info = {"version": "1.0.0", "author": "Test", "capabilities": ["crack", "analyze"]}

        app_context.register_plugin("test-plugin", plugin_info)

        loaded_plugins = app_context.get_loaded_plugins()
        assert "test-plugin" in loaded_plugins
        assert loaded_plugins["test-plugin"]["info"] == plugin_info
        assert "loaded_at" in loaded_plugins["test-plugin"]

    def test_unregister_plugin_removes_from_registry(self, app_context: AppContext) -> None:
        """Unregistering plugin removes it from loaded plugins."""
        app_context.register_plugin("test-plugin", {"version": "1.0.0"})

        assert "test-plugin" in app_context.get_loaded_plugins()

        app_context.unregister_plugin("test-plugin")

        assert "test-plugin" not in app_context.get_loaded_plugins()

    def test_register_plugin_emits_signal(self, app_context: AppContext) -> None:
        """Registering plugin emits plugin_loaded signal."""
        signal_emitted = False
        emitted_name = None
        emitted_info = None

        def signal_handler(name: str, info: dict[str, Any]) -> None:
            nonlocal signal_emitted, emitted_name, emitted_info
            signal_emitted = True
            emitted_name = name
            emitted_info = info

        if app_context.plugin_loaded:
            app_context.plugin_loaded.connect(signal_handler)

        plugin_info = {"version": "2.0.0"}
        app_context.register_plugin("test-plugin", plugin_info)

        if app_context.plugin_loaded:
            assert signal_emitted
            assert emitted_name == "test-plugin"
            assert emitted_info == plugin_info

    def test_unregister_plugin_emits_signal(self, app_context: AppContext) -> None:
        """Unregistering plugin emits plugin_unloaded signal."""
        app_context.register_plugin("test-plugin", {"version": "1.0.0"})

        signal_emitted = False
        emitted_name = None

        def signal_handler(name: str) -> None:
            nonlocal signal_emitted, emitted_name
            signal_emitted = True
            emitted_name = name

        if app_context.plugin_unloaded:
            app_context.plugin_unloaded.connect(signal_handler)

        app_context.unregister_plugin("test-plugin")

        if app_context.plugin_unloaded:
            assert signal_emitted
            assert emitted_name == "test-plugin"


class TestAppContextModelManagement:
    """Test AI model registration and tracking."""

    def test_register_model_adds_to_loaded_models(self, app_context: AppContext) -> None:
        """Registering model adds it to loaded models registry."""
        model_info = {"provider": "openai", "version": "gpt-4", "max_tokens": 8192}

        app_context.register_model("gpt-4", model_info)

        loaded_models = app_context.get_loaded_models()
        assert "gpt-4" in loaded_models
        assert loaded_models["gpt-4"]["info"] == model_info
        assert "loaded_at" in loaded_models["gpt-4"]

    def test_unregister_model_removes_from_registry(self, app_context: AppContext) -> None:
        """Unregistering model removes it from loaded models."""
        app_context.register_model("gpt-4", {"provider": "openai"})

        assert "gpt-4" in app_context.get_loaded_models()

        app_context.unregister_model("gpt-4")

        assert "gpt-4" not in app_context.get_loaded_models()


class TestAppContextTaskManagement:
    """Test task registration and progress tracking."""

    def test_register_task_adds_to_active_tasks(self, app_context: AppContext) -> None:
        """Registering task adds it to active tasks."""
        app_context.register_task("task-001", "Analyzing binary protections")

        active_tasks = app_context.get_active_tasks()
        assert "task-001" in active_tasks
        assert active_tasks["task-001"]["description"] == "Analyzing binary protections"
        assert active_tasks["task-001"]["progress"] == 0
        assert "started_at" in active_tasks["task-001"]

    def test_update_task_progress(self, app_context: AppContext) -> None:
        """Updating task progress modifies progress value."""
        app_context.register_task("task-001", "Processing")

        app_context.update_task_progress("task-001", 50)

        active_tasks = app_context.get_active_tasks()
        assert active_tasks["task-001"]["progress"] == 50

    def test_complete_task_removes_from_active_tasks(self, app_context: AppContext) -> None:
        """Completing task removes it from active tasks."""
        app_context.register_task("task-001", "Cracking license")

        assert "task-001" in app_context.get_active_tasks()

        app_context.complete_task("task-001", {"success": True})

        assert "task-001" not in app_context.get_active_tasks()

    def test_fail_task_removes_from_active_tasks(self, app_context: AppContext) -> None:
        """Failing task removes it from active tasks."""
        app_context.register_task("task-001", "Bypassing protection")

        assert "task-001" in app_context.get_active_tasks()

        app_context.fail_task("task-001", "Protection too complex")

        assert "task-001" not in app_context.get_active_tasks()

    def test_fail_task_stores_failed_task_info(self, app_context: AppContext) -> None:
        """Failing task stores failure information."""
        app_context.register_task("task-001", "Analyzing VMProtect")

        app_context.fail_task("task-001", "Analysis timeout")

        assert "failed_tasks" in app_context._state
        failed_tasks = app_context._state["failed_tasks"]
        assert len(failed_tasks) == 1
        assert failed_tasks[0]["task_id"] == "task-001"
        assert failed_tasks[0]["error_message"] == "Analysis timeout"
        assert "failed_at" in failed_tasks[0]

    def test_register_task_emits_signal(self, app_context: AppContext) -> None:
        """Registering task emits task_started signal."""
        signal_emitted = False
        emitted_id = None
        emitted_description = None

        def signal_handler(task_id: str, description: str) -> None:
            nonlocal signal_emitted, emitted_id, emitted_description
            signal_emitted = True
            emitted_id = task_id
            emitted_description = description

        if app_context.task_started:
            app_context.task_started.connect(signal_handler)

        app_context.register_task("task-001", "Cracking serial")

        if app_context.task_started:
            assert signal_emitted
            assert emitted_id == "task-001"
            assert emitted_description == "Cracking serial"

    def test_update_task_progress_emits_signal(self, app_context: AppContext) -> None:
        """Updating task progress emits task_progress signal."""
        app_context.register_task("task-001", "Processing")

        signal_emitted = False
        emitted_id = None
        emitted_progress = None

        def signal_handler(task_id: str, progress: int) -> None:
            nonlocal signal_emitted, emitted_id, emitted_progress
            signal_emitted = True
            emitted_id = task_id
            emitted_progress = progress

        if app_context.task_progress:
            app_context.task_progress.connect(signal_handler)

        app_context.update_task_progress("task-001", 75)

        if app_context.task_progress:
            assert signal_emitted
            assert emitted_id == "task-001"
            assert emitted_progress == 75

    def test_complete_task_emits_signal(self, app_context: AppContext) -> None:
        """Completing task emits task_completed signal."""
        app_context.register_task("task-001", "Finishing")

        signal_emitted = False
        emitted_id = None
        emitted_result = None

        def signal_handler(task_id: str, result: Any) -> None:
            nonlocal signal_emitted, emitted_id, emitted_result
            signal_emitted = True
            emitted_id = task_id
            emitted_result = result

        if app_context.task_completed:
            app_context.task_completed.connect(signal_handler)

        app_context.complete_task("task-001", {"crack_successful": True})

        if app_context.task_completed:
            assert signal_emitted
            assert emitted_id == "task-001"
            assert emitted_result is not None
            assert emitted_result["crack_successful"] is True

    def test_fail_task_emits_signal(self, app_context: AppContext) -> None:
        """Failing task emits task_failed signal."""
        app_context.register_task("task-001", "Failing")

        signal_emitted = False
        emitted_id = None
        emitted_error = None

        def signal_handler(task_id: str, error: str) -> None:
            nonlocal signal_emitted, emitted_id, emitted_error
            signal_emitted = True
            emitted_id = task_id
            emitted_error = error

        if app_context.task_failed:
            app_context.task_failed.connect(signal_handler)

        app_context.fail_task("task-001", "Failed to crack protection")

        if app_context.task_failed:
            assert signal_emitted
            assert emitted_id == "task-001"
            assert emitted_error == "Failed to crack protection"


class TestAppContextSettingsManagement:
    """Test application settings storage and retrieval."""

    def test_set_setting_stores_value(self, app_context: AppContext) -> None:
        """Setting value stores correctly in settings."""
        app_context.set_setting("theme", "dark")

        assert app_context.get_setting("theme") == "dark"

    def test_get_setting_returns_default_when_not_found(self, app_context: AppContext) -> None:
        """Getting nonexistent setting returns default value."""
        result = app_context.get_setting("nonexistent", "default_value")

        assert result == "default_value"

    def test_get_all_settings_returns_all_values(self, app_context: AppContext) -> None:
        """Getting all settings returns complete settings dict."""
        app_context.set_setting("setting1", "value1")
        app_context.set_setting("setting2", "value2")

        all_settings = app_context.get_all_settings()

        assert all_settings["setting1"] == "value1"
        assert all_settings["setting2"] == "value2"

    def test_set_setting_emits_signal(self, app_context: AppContext) -> None:
        """Setting value emits settings_changed signal."""
        signal_emitted = False
        emitted_key = None
        emitted_value = None

        def signal_handler(key: str, value: Any) -> None:
            nonlocal signal_emitted, emitted_key, emitted_value
            signal_emitted = True
            emitted_key = key
            emitted_value = value

        if app_context.settings_changed:
            app_context.settings_changed.connect(signal_handler)

        app_context.set_setting("auto_crack", True)

        if app_context.settings_changed:
            assert signal_emitted
            assert emitted_key == "auto_crack"
            assert emitted_value is True


class TestAppContextSessionHistory:
    """Test session history tracking."""

    def test_add_to_session_history_stores_entry(self, app_context: AppContext) -> None:
        """Adding to session history stores entry with timestamp."""
        app_context.add_to_session_history("binary_loaded", {"path": "/path/to/binary.exe"})

        history = app_context.get_session_history()

        assert len(history) == 1
        assert history[0]["action"] == "binary_loaded"
        assert history[0]["details"]["path"] == "/path/to/binary.exe"
        assert "timestamp" in history[0]

    def test_session_history_limited_to_1000_entries(self, app_context: AppContext) -> None:
        """Session history limited to 1000 most recent entries."""
        for i in range(1500):
            app_context.add_to_session_history(f"action_{i}", {"index": i})

        history = app_context.get_session_history()

        assert len(history) == 1000
        assert history[0]["details"]["index"] == 500
        assert history[-1]["details"]["index"] == 1499


class TestAppContextStateManagement:
    """Test state management and reset operations."""

    def test_get_full_state_returns_complete_state(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Get full state returns complete application state."""
        app_context.load_binary(str(temp_binary_file))
        app_context.set_analysis_results("scan", {"data": "value"})

        state = app_context.get_full_state()

        assert "current_binary" in state
        assert "analysis_results" in state
        assert "loaded_plugins" in state
        assert "settings" in state
        assert "active_tasks" in state

    def test_reset_state_clears_all_data(self, app_context: AppContext, temp_binary_file: Path) -> None:
        """Reset state clears all application data."""
        app_context.load_binary(str(temp_binary_file))
        app_context.set_analysis_results("scan", {"data": "value"})
        app_context.register_task("task-001", "Processing")

        app_context.reset_state()

        assert app_context.get_current_binary() is None
        assert len(app_context.get_analysis_results()) == 0
        assert len(app_context.get_active_tasks()) == 0
        assert len(app_context.get_session_history()) == 0


class TestAppContextSingleton:
    """Test singleton pattern for global app context."""

    def test_get_app_context_returns_singleton(self) -> None:
        """get_app_context returns same instance on multiple calls."""
        context1 = get_app_context()
        context2 = get_app_context()

        assert context1 is context2

    def test_get_app_context_creates_instance_on_first_call(self) -> None:
        """get_app_context creates instance on first call."""
        import intellicrack.core.app_context as module

        original = module._app_context_instance
        module._app_context_instance = None

        try:
            context = get_app_context()
            assert context is not None
            assert isinstance(context, AppContext)
        finally:
            module._app_context_instance = original
