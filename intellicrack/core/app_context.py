"""Application context management for Intellicrack.

This module provides centralized application context management including
configuration, state management, and shared resources across the application.

The AppContext class manages global application state and provides signals for
state changes, enabling decoupled communication between UI components. It handles
binary file management, project persistence, analysis result tracking, plugin
registration, AI model management, task coordination, settings management, and
session history.

Copyright (C) 2025 Zachary Flint

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

import json
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from intellicrack.handlers.pyqt6_handler import PYQT6_AVAILABLE, QObject, pyqtSignal
from intellicrack.utils.logger import get_logger
from intellicrack.utils.type_safety import get_typed_item, validate_type


logger = get_logger(__name__)


if PYQT6_AVAILABLE:

    class AppContext(QObject):
        """Centralized application state manager.

        Manages global application state and provides signals for state changes,
        enabling decoupled communication between UI components.
        """

        binary_loaded = pyqtSignal(dict)
        binary_unloaded = pyqtSignal()
        project_loaded = pyqtSignal(dict)
        project_saved = pyqtSignal(str)
        project_closed = pyqtSignal()
        plugin_loaded = pyqtSignal(str, dict)
        plugin_unloaded = pyqtSignal(str)
        settings_changed = pyqtSignal(str, object)
        task_started = pyqtSignal(str, str)
        task_progress = pyqtSignal(str, int)
        task_completed = pyqtSignal(str, object)
        task_failed = pyqtSignal(str, str)
        log_message = pyqtSignal(str, str)
        application_quitting = pyqtSignal()
        analysis_started = pyqtSignal(str, dict)
        analysis_completed = pyqtSignal(str, dict)
        analysis_failed = pyqtSignal(str, str)
        model_loaded = pyqtSignal(str, dict)
        model_unloaded = pyqtSignal(str)

        def __init__(self) -> None:
            """Initialize the application context.

            Sets up the application context with state management for binaries,
            projects, analysis results, plugins, models, settings, and active
            tasks. Initializes signal-slot connections and observer patterns
            for communication between different components of the application.
            """
            super().__init__()
            self._state: dict[str, Any] = {
                "current_binary": None,
                "current_project": None,
                "analysis_results": {},
                "loaded_plugins": {},
                "loaded_models": {},
                "settings": {},
                "active_tasks": {},
                "session_history": [],
                "recent_files": [],
                "recent_projects": [],
            }
            self._observers: dict[str, Any] = {}
            logger.info("AppContext initialized")

        # Binary Management
        def load_binary(self, file_path: str, metadata: dict[str, Any] | None = None) -> bool:
            """Load a binary file and emit appropriate signals.

            Loads a binary file from the specified path, validates its existence,
            retrieves file metadata, stores binary information in application state,
            adds it to recent files, and emits the binary_loaded signal.

            Args:
                file_path: Path to the binary file to load.
                metadata: Optional metadata dictionary to associate with the binary.

            Returns:
                bool: True if the binary was loaded successfully, False if the file
                    does not exist or file stats cannot be retrieved.

            Raises:
                Exception: Catches and logs any unexpected errors during binary loading.
            """
            try:
                path = Path(file_path)
                if not path.exists():
                    logger.error("Binary file not found: %s", file_path)
                    return False

                try:
                    stat_info = path.stat()
                    file_size = stat_info.st_size
                except OSError:
                    logger.exception("Failed to get file stats for %s", file_path)
                    return False

                binary_info: dict[str, Any] = {
                    "path": str(path.absolute()),
                    "name": path.name,
                    "size": file_size,
                    "loaded_at": datetime.now().isoformat(),
                    "metadata": metadata or {},
                }

                self._state["current_binary"] = binary_info
                self._add_to_recent_files(str(path.absolute()))

                logger.info("Binary loaded: %s (%s bytes)", path.name, file_size)
                self.binary_loaded.emit(binary_info)
                return True

            except Exception:
                logger.exception("Failed to load binary")
                return False

        def unload_binary(self) -> None:
            """Unload the current binary.

            Clears the currently loaded binary and associated analysis results,
            and emits the binary_unloaded signal to notify listeners of the change.

            Raises:
                None: This method catches all exceptions internally.
            """
            if current_binary := self._state["current_binary"]:
                if isinstance(current_binary, dict):
                    logger.info("Unloading binary: %s", current_binary.get("name", "unknown"))
                self._state["current_binary"] = None
                analysis_results = self._state["analysis_results"]
                if isinstance(analysis_results, dict):
                    analysis_results.clear()
                self.binary_unloaded.emit()

        def get_current_binary(self) -> dict[str, Any] | None:
            """Get information about the currently loaded binary.

            Returns:
                dict[str, Any] | None: Dictionary containing binary metadata (path,
                    name, size, loaded_at, metadata) if a binary is loaded,
                    None otherwise.

            Raises:
                None: This method does not raise exceptions.
            """
            result = self._state["current_binary"]
            if result is None or isinstance(result, dict):
                return validate_type(result, dict) if result is not None else None
            return None

        # Analysis Results Management
        def set_analysis_results(self, analysis_type: str, results: dict[str, Any]) -> None:
            """Store analysis results and emit completion signal.

            Stores analysis results in the application state indexed by analysis type,
            and emits the analysis_completed signal to notify listeners of the results.

            Args:
                analysis_type: Type of analysis being stored (e.g., 'entropy',
                    'protection_detection').
                results: Dictionary of analysis results keyed by result type.

            Raises:
                None: This method does not raise exceptions.
            """
            analysis_results = self._state["analysis_results"]
            if isinstance(analysis_results, dict):
                analysis_results[analysis_type] = {
                    "results": results,
                    "timestamp": datetime.now().isoformat(),
                }
            logger.info("Analysis completed: %s. Results keys: %s", analysis_type, list(results.keys()))
            self.analysis_completed.emit(analysis_type, results)

        def get_analysis_results(self, analysis_type: str | None = None) -> dict[str, Any]:
            """Get analysis results for a specific type or all results.

            Args:
                analysis_type: Optional type of analysis to retrieve. If None,
                    returns all analysis results.

            Returns:
                dict[str, Any]: Dictionary of analysis results for the specified type
                    or all results if analysis_type is None.

            Raises:
                None: This method does not raise exceptions.
            """
            analysis_results = self._state["analysis_results"]
            if not isinstance(analysis_results, dict):
                return {}
            if analysis_type:
                result = analysis_results.get(analysis_type, {})
                return validate_type(result, dict) if isinstance(result, dict) else {}
            return validate_type(analysis_results, dict)

        def start_analysis(self, analysis_type: str, options: dict[str, Any] | None = None) -> None:
            """Signal that an analysis has started.

            Emits the analysis_started signal to notify listeners that a new analysis
            operation is beginning with the specified type and options.

            Args:
                analysis_type: Type of analysis being started (e.g., 'entropy',
                    'protection_detection').
                options: Optional dictionary of analysis options and configuration
                    parameters.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.info("Analysis started: %s", analysis_type)
            self.analysis_started.emit(analysis_type, options or {})

        def fail_analysis(self, analysis_type: str, error_message: str) -> None:
            """Signal that an analysis has failed.

            Emits the analysis_failed signal to notify listeners that an analysis
            operation has encountered an error and cannot continue.

            Args:
                analysis_type: Type of analysis that failed.
                error_message: Description of the error that occurred during analysis.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.error("Analysis failed: %s - %s", analysis_type, error_message)
            self.analysis_failed.emit(analysis_type, error_message)

        # Project Management
        def load_project(self, project_path: str) -> bool:
            """Load a project from file.

            Loads a project configuration from the specified file path, validates
            the JSON structure, restores associated binary and analysis results,
            and emits the project_loaded signal.

            Args:
                project_path: Path to the project file to load.

            Returns:
                bool: True if the project was loaded successfully, False if the file
                    does not exist or contains invalid JSON.

            Raises:
                Exception: Catches and logs any unexpected errors during project loading.
            """
            try:
                path = Path(project_path)
                if not path.exists():
                    logger.error("Project file not found: %s", project_path)
                    return False

                try:
                    with open(path) as f:
                        project_data = json.load(f)
                except json.JSONDecodeError:
                    logger.exception("Invalid project JSON in %s", project_path)
                    return False
                except OSError:
                    logger.exception("Failed to read project file %s", project_path)
                    return False

                project_info: dict[str, Any] = {
                    "path": str(path.absolute()),
                    "name": project_data.get("name", path.stem),
                    "data": project_data,
                    "loaded_at": datetime.now().isoformat(),
                }

                self._state["current_project"] = project_info
                self._add_to_recent_projects(str(path.absolute()))

                # Load associated binary if specified
                binary_path = project_data.get("binary_path")
                if binary_path and isinstance(binary_path, str):
                    self.load_binary(binary_path)

                # Restore analysis results if present
                analysis_results = project_data.get("analysis_results")
                if analysis_results and isinstance(analysis_results, dict):
                    self._state["analysis_results"] = analysis_results

                logger.info("Project loaded: %s from %s", project_info["name"], project_path)
                self.project_loaded.emit(project_info)
                return True

            except Exception:
                logger.exception("Failed to load project")
                return False

        def save_project(self, project_path: str) -> bool:
            """Save current state as a project.

            Serializes the current binary, analysis results, and settings to a JSON
            project file at the specified path. Creates parent directories if needed.

            Args:
                project_path: Path where the project file should be saved.

            Returns:
                bool: True if the project was saved successfully, False if the
                    directory cannot be created or the file cannot be written.

            Raises:
                Exception: Catches and logs any unexpected errors during project saving.
            """
            try:
                current_binary = self._state["current_binary"]
                binary_path_value: str | None = None
                if current_binary and isinstance(current_binary, dict):
                    binary_path_value = get_typed_item(current_binary, "path", str)

                project_data: dict[str, Any] = {
                    "name": Path(project_path).stem,
                    "created_at": datetime.now().isoformat(),
                    "binary_path": binary_path_value,
                    "analysis_results": self._state["analysis_results"],
                    "settings": self._state["settings"],
                }

                path = Path(project_path)
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                except OSError:
                    logger.exception("Failed to create project directory %s", path.parent)
                    return False

                try:
                    with open(path, "w") as f:
                        json.dump(project_data, f, indent=2)
                except OSError:
                    logger.exception("Failed to save project to %s", path)
                    return False

                self._state["current_project"] = {
                    "path": str(path.absolute()),
                    "name": project_data["name"],
                    "data": project_data,
                }

                logger.info("Project saved: %s", project_path)
                self.project_saved.emit(str(path.absolute()))
                return True

            except Exception:
                logger.exception("Failed to save project")
                return False

        def close_project(self) -> None:
            """Close the current project.

            Clears the currently loaded project and emits the project_closed signal
            to notify listeners of the project closure.

            Raises:
                None: This method does not raise exceptions.
            """
            if current_project := self._state["current_project"]:
                if isinstance(current_project, dict):
                    logger.info("Closing project: %s", current_project.get("name", "unknown"))
                self._state["current_project"] = None
                self.project_closed.emit()

        # Plugin Management
        def register_plugin(self, plugin_name: str, plugin_info: dict[str, Any]) -> None:
            """Register a loaded plugin.

            Stores plugin metadata in the application state and emits the
            plugin_loaded signal to notify listeners of the new plugin registration.

            Args:
                plugin_name: Name of the plugin being registered.
                plugin_info: Dictionary containing plugin metadata and configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            if isinstance(loaded_plugins, dict):
                loaded_plugins[plugin_name] = {
                    "info": plugin_info,
                    "loaded_at": datetime.now().isoformat(),
                }
            logger.info("Plugin registered: %s", plugin_name)
            self.plugin_loaded.emit(plugin_name, plugin_info)

        def unregister_plugin(self, plugin_name: str) -> None:
            """Unregister a plugin.

            Removes plugin metadata from the application state and emits the
            plugin_unloaded signal to notify listeners of the plugin removal.

            Args:
                plugin_name: Name of the plugin to unregister.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            if isinstance(loaded_plugins, dict) and plugin_name in loaded_plugins:
                del loaded_plugins[plugin_name]
                logger.info("Plugin unregistered: %s", plugin_name)
                self.plugin_unloaded.emit(plugin_name)

        def get_loaded_plugins(self) -> dict[str, Any]:
            """Get information about all loaded plugins.

            Returns:
                dict[str, Any]: Dictionary of all currently loaded plugins with their
                    metadata keyed by plugin name.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            return validate_type(loaded_plugins, dict) if isinstance(loaded_plugins, dict) else {}

        # Model Management
        def register_model(self, model_name: str, model_info: dict[str, Any]) -> None:
            """Register a loaded AI model.

            Stores AI model metadata in the application state and emits the
            model_loaded signal to notify listeners of the new model registration.

            Args:
                model_name: Name of the AI model being registered.
                model_info: Dictionary containing model metadata and configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            if isinstance(loaded_models, dict):
                loaded_models[model_name] = {
                    "info": model_info,
                    "loaded_at": datetime.now().isoformat(),
                }
            logger.info("Model registered: %s", model_name)
            self.model_loaded.emit(model_name, model_info)

        def unregister_model(self, model_name: str) -> None:
            """Unregister an AI model.

            Removes AI model metadata from the application state and emits the
            model_unloaded signal to notify listeners of the model removal.

            Args:
                model_name: Name of the AI model to unregister.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            if isinstance(loaded_models, dict) and model_name in loaded_models:
                del loaded_models[model_name]
                logger.info("Model unregistered: %s", model_name)
                self.model_unloaded.emit(model_name)

        def get_loaded_models(self) -> dict[str, Any]:
            """Get information about all loaded models.

            Returns:
                dict[str, Any]: Dictionary of all currently loaded AI models with their
                    metadata keyed by model name.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            return validate_type(loaded_models, dict) if isinstance(loaded_models, dict) else {}

        # Task Management
        def register_task(self, task_id: str, description: str) -> None:
            """Register a new task.

            Creates a new task entry in the application state with initial progress
            and emits the task_started signal to notify listeners of the new task.

            Args:
                task_id: Unique identifier for the task.
                description: Human-readable description of the task being registered.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict):
                active_tasks[task_id] = {
                    "description": description,
                    "started_at": datetime.now().isoformat(),
                    "progress": 0,
                }
            logger.info("Task registered: %s - %s", task_id, description)
            self.task_started.emit(task_id, description)

        def update_task_progress(self, task_id: str, progress: int) -> None:
            """Update task progress.

            Updates the progress percentage for an active task and emits the
            task_progress signal to notify listeners of the update.

            Args:
                task_id: Identifier of the task to update.
                progress: Progress percentage as integer between 0 and 100.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_data = active_tasks[task_id]
                if isinstance(task_data, dict):
                    task_data["progress"] = progress
                self.task_progress.emit(task_id, progress)

        def complete_task(self, task_id: str, result: object = None) -> None:
            """Mark a task as completed.

            Removes the task from active tasks and emits the task_completed signal
            to notify listeners that the task has finished with the given result.

            Args:
                task_id: Identifier of the task to complete.
                result: Optional result object from the task execution.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_info = active_tasks.pop(task_id)
                if isinstance(task_info, dict):
                    logger.info("Task completed: %s - %s", task_id, task_info.get("description", "unknown"))
                self.task_completed.emit(task_id, result)

        def fail_task(self, task_id: str, error_message: str) -> None:
            """Mark a task as failed.

            Removes the task from active tasks, stores failure information in history,
            and emits the task_failed signal to notify listeners of the task failure.

            Args:
                task_id: Identifier of the task that failed.
                error_message: Description of the error that occurred during task
                    execution.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_info = active_tasks.pop(task_id)

                failed_task: dict[str, Any] = {
                    "task_id": task_id,
                    "original_info": task_info,
                    "error_message": error_message,
                    "failed_at": self._get_timestamp(),
                }

                if "failed_tasks" not in self._state:
                    self._state["failed_tasks"] = []
                failed_tasks = self._state["failed_tasks"]
                if isinstance(failed_tasks, list):
                    failed_tasks.append(failed_task)

                description = "N/A"
                if isinstance(task_info, dict):
                    description = get_typed_item(task_info, "description", str, "N/A")

                logger.error(
                    "Task failed: %s (%s) - %s",
                    task_id,
                    description,
                    error_message,
                )
                self.task_failed.emit(task_id, error_message)

        def get_active_tasks(self) -> dict[str, Any]:
            """Get all active tasks.

            Returns:
                dict[str, Any]: Dictionary of all active tasks with task_id as keys
                    and task metadata as values.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            return validate_type(active_tasks, dict) if isinstance(active_tasks, dict) else {}

        # Settings Management
        def set_setting(self, key: str, value: object) -> None:
            """Update a setting value.

            Stores the setting value in the application state and emits the
            settings_changed signal to notify listeners of the configuration change.

            Args:
                key: The setting key to update.
                value: The new value for the setting.

            Raises:
                None: This method does not raise exceptions.
            """
            settings = self._state["settings"]
            if isinstance(settings, dict):
                old_value = settings.get(key)
                settings[key] = value

                if old_value != value:
                    logger.info("Setting changed: %s = %s (was: %s)", key, value, old_value)
                else:
                    logger.debug("Setting updated (no change): %s = %s", key, value)

            self.settings_changed.emit(key, value)

        def get_setting(self, key: str, default: object = None) -> object:
            """Get a setting value.

            Args:
                key: The setting key to retrieve.
                default: Default value to return if key is not found.

            Returns:
                The setting value associated with the key, or default if not found.
            """
            settings = self._state["settings"]
            return settings.get(key, default) if isinstance(settings, dict) else default

        def get_all_settings(self) -> dict[str, Any]:
            """Get all settings.

            Returns:
                dict[str, Any]: Dictionary of all settings with keys as setting names
                    and values as setting values.

            Raises:
                None: This method does not raise exceptions.
            """
            settings = self._state["settings"]
            return validate_type(settings, dict) if isinstance(settings, dict) else {}

        # History Management
        def add_to_session_history(self, action: str, details: dict[str, Any]) -> None:
            """Add an action to the session history.

            Args:
                action: Description of the action performed.
                details: Dictionary containing details about the action.

            Raises:
                None: This method does not raise exceptions.
            """
            entry: dict[str, Any] = {
                "action": action,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            }
            session_history = self._state["session_history"]
            if isinstance(session_history, list):
                session_history.append(entry)

                # Keep only last 1000 entries
                if len(session_history) > 1000:
                    self._state["session_history"] = session_history[-1000:]

        def get_session_history(self) -> list[dict[str, Any]]:
            """Get the session history.

            Returns:
                list[dict[str, Any]]: List of session history entries with action and
                    timestamp information.

            Raises:
                None: This method does not raise exceptions.
            """
            session_history = self._state["session_history"]
            return validate_type(session_history, list) if isinstance(session_history, list) else []

        def get_recent_files(self) -> list[str]:
            """Get list of recently opened files.

            Returns:
                list[str]: List of file paths ordered by most recent first (up to
                    10 entries).

            Raises:
                None: This method does not raise exceptions.
            """
            recent_files = self._state["recent_files"]
            return validate_type(recent_files, list) if isinstance(recent_files, list) else []

        def get_recent_projects(self) -> list[str]:
            """Get list of recently opened projects.

            Returns:
                list[str]: List of project paths ordered by most recent first (up to
                    10 entries).

            Raises:
                None: This method does not raise exceptions.
            """
            recent_projects = self._state["recent_projects"]
            return validate_type(recent_projects, list) if isinstance(recent_projects, list) else []

        def _get_timestamp(self) -> str:
            """Return a formatted timestamp string.

            Returns:
                str: ISO format timestamp string representing the current time.

            Raises:
                None: This method does not raise exceptions.
            """
            return datetime.now().isoformat()

        # Private helper methods
        def _add_to_recent_files(self, file_path: str) -> None:
            """Add a file to the recent files list.

            Args:
                file_path: Path to the file to add to recent files.

            Raises:
                None: This method does not raise exceptions.
            """
            recent_files = self._state["recent_files"]
            if isinstance(recent_files, list):
                if file_path in recent_files:
                    recent_files.remove(file_path)
                recent_files.insert(0, file_path)
                self._state["recent_files"] = recent_files[:10]

        def _add_to_recent_projects(self, project_path: str) -> None:
            """Add a project to the recent projects list.

            Args:
                project_path: Path to the project to add to recent projects.

            Raises:
                None: This method does not raise exceptions.
            """
            recent_projects = self._state["recent_projects"]
            if isinstance(recent_projects, list):
                if project_path in recent_projects:
                    recent_projects.remove(project_path)
                recent_projects.insert(0, project_path)
                self._state["recent_projects"] = recent_projects[:10]

        # State observation for debugging
        def get_full_state(self) -> dict[str, Any]:
            """Get the complete application state (for debugging).

            Returns:
                dict[str, Any]: Copy of the entire application state dictionary.

            Raises:
                None: This method does not raise exceptions.
            """
            return self._state.copy()

        def reset_state(self) -> None:
            """Reset the application state to defaults.

            Clears all active tasks, analysis results, and history while preserving
            settings configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.warning("Resetting application state")
            self.unload_binary()
            self.close_project()
            analysis_results = self._state["analysis_results"]
            if isinstance(analysis_results, dict):
                analysis_results.clear()
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict):
                active_tasks.clear()
            session_history = self._state["session_history"]
            if isinstance(session_history, list):
                session_history.clear()

else:

    class AppContext:
        """Centralized application state manager.

        Manages global application state and provides signals for state changes,
        enabling decoupled communication between UI components.
        """

        binary_loaded = None
        binary_unloaded = None
        project_loaded = None
        project_saved = None
        project_closed = None
        plugin_loaded = None
        plugin_unloaded = None
        settings_changed = None
        task_started = None
        task_progress = None
        task_completed = None
        task_failed = None
        log_message = None
        application_quitting = None
        analysis_started = None
        analysis_completed = None
        analysis_failed = None
        model_loaded = None
        model_unloaded = None

        def __init__(self) -> None:
            """Initialize the application context.

            Sets up the application context with state management for binaries,
            projects, analysis results, plugins, models, settings, and active
            tasks. Initializes signal-slot connections and observer patterns
            for communication between different components of the application.
            """
            self._state: dict[str, Any] = {
                "current_binary": None,
                "current_project": None,
                "analysis_results": {},
                "loaded_plugins": {},
                "loaded_models": {},
                "settings": {},
                "active_tasks": {},
                "session_history": [],
                "recent_files": [],
                "recent_projects": [],
            }
            self._observers: dict[str, Any] = {}
            logger.info("AppContext initialized")

        # Binary Management
        def load_binary(self, file_path: str, metadata: dict[str, Any] | None = None) -> bool:
            """Load a binary file and emit appropriate signals.

            Loads a binary file from the specified path, validates its existence,
            retrieves file metadata, stores binary information in application state,
            adds it to recent files.

            Args:
                file_path: Path to the binary file to load.
                metadata: Optional metadata dictionary to associate with the binary.

            Returns:
                bool: True if the binary was loaded successfully, False if the file
                    does not exist or file stats cannot be retrieved.

            Raises:
                Exception: Catches and logs any unexpected errors during binary loading.
            """
            try:
                path = Path(file_path)
                if not path.exists():
                    logger.error("Binary file not found: %s", file_path)
                    return False

                try:
                    stat_info = path.stat()
                    file_size = stat_info.st_size
                except OSError:
                    logger.exception("Failed to get file stats for %s", file_path)
                    return False

                binary_info: dict[str, Any] = {
                    "path": str(path.absolute()),
                    "name": path.name,
                    "size": file_size,
                    "loaded_at": datetime.now().isoformat(),
                    "metadata": metadata or {},
                }

                self._state["current_binary"] = binary_info
                self._add_to_recent_files(str(path.absolute()))

                logger.info("Binary loaded: %s (%s bytes)", path.name, file_size)
                return True

            except Exception:
                logger.exception("Failed to load binary")
                return False

        def unload_binary(self) -> None:
            """Unload the current binary.

            Clears the currently loaded binary and associated analysis results
            to prepare for loading a different binary or shutdown.

            Raises:
                None: This method does not raise exceptions.
            """
            if current_binary := self._state["current_binary"]:
                if isinstance(current_binary, dict):
                    logger.info("Unloading binary: %s", current_binary.get("name", "unknown"))
                self._state["current_binary"] = None
                analysis_results = self._state["analysis_results"]
                if isinstance(analysis_results, dict):
                    analysis_results.clear()

        def get_current_binary(self) -> dict[str, Any] | None:
            """Get information about the currently loaded binary.

            Returns:
                dict[str, Any] | None: Dictionary containing binary metadata (path,
                    name, size, loaded_at, metadata) if a binary is loaded,
                    None otherwise.

            Raises:
                None: This method does not raise exceptions.
            """
            result = self._state["current_binary"]
            if result is None or isinstance(result, dict):
                return cast("dict[str, Any] | None", result)
            return None

        # Analysis Results Management
        def set_analysis_results(self, analysis_type: str, results: dict[str, Any]) -> None:
            """Store analysis results and emit completion signal.

            Stores analysis results in the application state indexed by analysis type
            with timestamp information for tracking when results were generated.

            Args:
                analysis_type: Type of analysis being stored (e.g., 'entropy',
                    'protection_detection').
                results: Dictionary of analysis results keyed by result type.

            Raises:
                None: This method does not raise exceptions.
            """
            analysis_results = self._state["analysis_results"]
            if isinstance(analysis_results, dict):
                analysis_results[analysis_type] = {
                    "results": results,
                    "timestamp": datetime.now().isoformat(),
                }
            logger.info("Analysis completed: %s. Results keys: %s", analysis_type, list(results.keys()))

        def get_analysis_results(self, analysis_type: str | None = None) -> dict[str, Any]:
            """Get analysis results for a specific type or all results.

            Args:
                analysis_type: Optional type of analysis to retrieve. If None,
                    returns all analysis results.

            Returns:
                dict[str, Any]: Dictionary of analysis results for the specified type
                    or all results if analysis_type is None.

            Raises:
                None: This method does not raise exceptions.
            """
            analysis_results = self._state["analysis_results"]
            if not isinstance(analysis_results, dict):
                return {}
            if analysis_type:
                result = analysis_results.get(analysis_type, {})
                return cast("dict[str, Any]", result) if isinstance(result, dict) else {}
            return cast("dict[str, Any]", analysis_results)

        def start_analysis(self, analysis_type: str, options: dict[str, Any] | None = None) -> None:
            """Signal that an analysis has started.

            Logs the start of a new analysis operation with the specified type and options.
            In non-PyQt6 environments, this method provides logging-only functionality.

            Args:
                analysis_type: Type of analysis being started (e.g., 'entropy',
                    'protection_detection').
                options: Optional dictionary of analysis options and configuration
                    parameters.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.info("Analysis started: %s", analysis_type)

        def fail_analysis(self, analysis_type: str, error_message: str) -> None:
            """Signal that an analysis has failed.

            Logs the failure of an analysis operation with error details.
            In non-PyQt6 environments, this method provides logging-only functionality.

            Args:
                analysis_type: Type of analysis that failed.
                error_message: Description of the error that occurred during analysis.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.error("Analysis failed: %s - %s", analysis_type, error_message)

        # Project Management
        def load_project(self, project_path: str) -> bool:
            """Load a project from file.

            Loads a project configuration from the specified file path, validates
            the JSON structure, restores associated binary and analysis results.

            Args:
                project_path: Path to the project file to load.

            Returns:
                bool: True if the project was loaded successfully, False if the file
                    does not exist or contains invalid JSON.

            Raises:
                Exception: Catches and logs any unexpected errors during project loading.
            """
            try:
                path = Path(project_path)
                if not path.exists():
                    logger.error("Project file not found: %s", project_path)
                    return False

                try:
                    with open(path) as f:
                        project_data = json.load(f)
                except json.JSONDecodeError:
                    logger.exception("Invalid project JSON in %s", project_path)
                    return False
                except OSError:
                    logger.exception("Failed to read project file %s", project_path)
                    return False

                project_info: dict[str, Any] = {
                    "path": str(path.absolute()),
                    "name": project_data.get("name", path.stem),
                    "data": project_data,
                    "loaded_at": datetime.now().isoformat(),
                }

                self._state["current_project"] = project_info
                self._add_to_recent_projects(str(path.absolute()))

                # Load associated binary if specified
                binary_path = project_data.get("binary_path")
                if binary_path and isinstance(binary_path, str):
                    self.load_binary(binary_path)

                # Restore analysis results if present
                analysis_results = project_data.get("analysis_results")
                if analysis_results and isinstance(analysis_results, dict):
                    self._state["analysis_results"] = analysis_results

                logger.info("Project loaded: %s from %s", project_info["name"], project_path)
                return True

            except Exception:
                logger.exception("Failed to load project")
                return False

        def save_project(self, project_path: str) -> bool:
            """Save current state as a project.

            Serializes the current binary, analysis results, and settings to a JSON
            project file at the specified path. Creates parent directories if needed.

            Args:
                project_path: Path where the project file should be saved.

            Returns:
                bool: True if the project was saved successfully, False if the
                    directory cannot be created or the file cannot be written.

            Raises:
                Exception: Catches and logs any unexpected errors during project saving.
            """
            try:
                current_binary = self._state["current_binary"]
                binary_path_value: str | None = None
                if current_binary and isinstance(current_binary, dict):
                    path_val = current_binary.get("path")
                    if isinstance(path_val, str):
                        binary_path_value = path_val

                project_data: dict[str, Any] = {
                    "name": Path(project_path).stem,
                    "created_at": datetime.now().isoformat(),
                    "binary_path": binary_path_value,
                    "analysis_results": self._state["analysis_results"],
                    "settings": self._state["settings"],
                }

                path = Path(project_path)
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                except OSError:
                    logger.exception("Failed to create project directory %s", path.parent)
                    return False

                try:
                    with open(path, "w") as f:
                        json.dump(project_data, f, indent=2)
                except OSError:
                    logger.exception("Failed to save project to %s", path)
                    return False

                self._state["current_project"] = {
                    "path": str(path.absolute()),
                    "name": project_data["name"],
                    "data": project_data,
                }

                logger.info("Project saved: %s", project_path)
                return True

            except Exception:
                logger.exception("Failed to save project")
                return False

        def close_project(self) -> None:
            """Close the current project.

            Clears the currently loaded project from the application state,
            making room for loading a different project or application shutdown.

            Raises:
                None: This method does not raise exceptions.
            """
            if current_project := self._state["current_project"]:
                if isinstance(current_project, dict):
                    logger.info("Closing project: %s", current_project.get("name", "unknown"))
                self._state["current_project"] = None

        # Plugin Management
        def register_plugin(self, plugin_name: str, plugin_info: dict[str, Any]) -> None:
            """Register a loaded plugin.

            Stores plugin metadata in the application state with registration timestamp
            for tracking loaded plugins and their configurations.

            Args:
                plugin_name: Name of the plugin being registered.
                plugin_info: Dictionary containing plugin metadata and configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            if isinstance(loaded_plugins, dict):
                loaded_plugins[plugin_name] = {
                    "info": plugin_info,
                    "loaded_at": datetime.now().isoformat(),
                }
            logger.info("Plugin registered: %s", plugin_name)

        def unregister_plugin(self, plugin_name: str) -> None:
            """Unregister a plugin.

            Removes plugin metadata from the application state to clean up
            after plugin unloading or application shutdown.

            Args:
                plugin_name: Name of the plugin to unregister.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            if isinstance(loaded_plugins, dict) and plugin_name in loaded_plugins:
                del loaded_plugins[plugin_name]
                logger.info("Plugin unregistered: %s", plugin_name)

        def get_loaded_plugins(self) -> dict[str, Any]:
            """Get information about all loaded plugins.

            Returns:
                dict[str, Any]: Dictionary of all currently loaded plugins with their
                    metadata keyed by plugin name.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_plugins = self._state["loaded_plugins"]
            return cast("dict[str, Any]", loaded_plugins) if isinstance(loaded_plugins, dict) else {}

        # Model Management
        def register_model(self, model_name: str, model_info: dict[str, Any]) -> None:
            """Register a loaded AI model.

            Stores AI model metadata in the application state with registration timestamp
            for tracking loaded models and their configurations.

            Args:
                model_name: Name of the AI model being registered.
                model_info: Dictionary containing model metadata and configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            if isinstance(loaded_models, dict):
                loaded_models[model_name] = {
                    "info": model_info,
                    "loaded_at": datetime.now().isoformat(),
                }
            logger.info("Model registered: %s", model_name)

        def unregister_model(self, model_name: str) -> None:
            """Unregister an AI model.

            Removes AI model metadata from the application state to clean up
            after model unloading or application shutdown.

            Args:
                model_name: Name of the AI model to unregister.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            if isinstance(loaded_models, dict) and model_name in loaded_models:
                del loaded_models[model_name]
                logger.info("Model unregistered: %s", model_name)

        def get_loaded_models(self) -> dict[str, Any]:
            """Get information about all loaded models.

            Returns:
                dict[str, Any]: Dictionary of all currently loaded AI models with their
                    metadata keyed by model name.

            Raises:
                None: This method does not raise exceptions.
            """
            loaded_models = self._state["loaded_models"]
            return cast("dict[str, Any]", loaded_models) if isinstance(loaded_models, dict) else {}

        # Task Management
        def register_task(self, task_id: str, description: str) -> None:
            """Register a new task.

            Creates a new task entry in the application state with initial progress
            set to zero and start timestamp recorded for tracking purposes.

            Args:
                task_id: Unique identifier for the task.
                description: Human-readable description of the task being registered.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict):
                active_tasks[task_id] = {
                    "description": description,
                    "started_at": datetime.now().isoformat(),
                    "progress": 0,
                }
            logger.info("Task registered: %s - %s", task_id, description)

        def update_task_progress(self, task_id: str, progress: int) -> None:
            """Update task progress.

            Updates the progress percentage for an active task in the application state,
            allowing callers to track the completion status of ongoing operations.

            Args:
                task_id: Identifier of the task to update.
                progress: Progress percentage as integer between 0 and 100.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_data = active_tasks[task_id]
                if isinstance(task_data, dict):
                    task_data["progress"] = progress

        def complete_task(self, task_id: str, result: object = None) -> None:
            """Mark a task as completed.

            Removes the task from the active tasks in the application state,
            logging the completion and any associated result or metadata.

            Args:
                task_id: Identifier of the task to complete.
                result: Optional result object from the task execution.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_info = active_tasks.pop(task_id)
                if isinstance(task_info, dict):
                    logger.info("Task completed: %s - %s", task_id, task_info.get("description", "unknown"))

        def fail_task(self, task_id: str, error_message: str) -> None:
            """Mark a task as failed.

            Removes the task from active tasks, stores failure information including
            the original task metadata and error details for auditing and debugging.

            Args:
                task_id: Identifier of the task that failed.
                error_message: Description of the error that occurred during task
                    execution.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict) and task_id in active_tasks:
                task_info = active_tasks.pop(task_id)

                failed_task: dict[str, Any] = {
                    "task_id": task_id,
                    "original_info": task_info,
                    "error_message": error_message,
                    "failed_at": self._get_timestamp(),
                }

                if "failed_tasks" not in self._state:
                    self._state["failed_tasks"] = []
                failed_tasks = self._state["failed_tasks"]
                if isinstance(failed_tasks, list):
                    failed_tasks.append(failed_task)

                description = "N/A"
                if isinstance(task_info, dict):
                    desc_val = task_info.get("description", "N/A")
                    description = str(desc_val) if desc_val is not None else "N/A"

                logger.error(
                    "Task failed: %s (%s) - %s",
                    task_id,
                    description,
                    error_message,
                )

        def get_active_tasks(self) -> dict[str, Any]:
            """Get all active tasks.

            Returns:
                dict[str, Any]: Dictionary of all active tasks with task_id as keys
                    and task metadata as values.

            Raises:
                None: This method does not raise exceptions.
            """
            active_tasks = self._state["active_tasks"]
            return cast("dict[str, Any]", active_tasks) if isinstance(active_tasks, dict) else {}

        # Settings Management
        def set_setting(self, key: str, value: object) -> None:
            """Update a setting value.

            Stores the setting value in the application state and logs the change
            to provide visibility into configuration modifications over time.

            Args:
                key: The setting key to update.
                value: The new value for the setting.

            Raises:
                None: This method does not raise exceptions.
            """
            settings = self._state["settings"]
            if isinstance(settings, dict):
                old_value = settings.get(key)
                settings[key] = value

                if old_value != value:
                    logger.info("Setting changed: %s = %s (was: %s)", key, value, old_value)
                else:
                    logger.debug("Setting updated (no change): %s = %s", key, value)

        def get_setting(self, key: str, default: object = None) -> object:
            """Get a setting value.

            Args:
                key: The setting key to retrieve.
                default: Default value to return if key is not found.

            Returns:
                The setting value associated with the key, or default if not found.
            """
            settings = self._state["settings"]
            return settings.get(key, default) if isinstance(settings, dict) else default

        def get_all_settings(self) -> dict[str, Any]:
            """Get all settings.

            Returns:
                dict[str, Any]: Dictionary of all settings with keys as setting names
                    and values as setting values.

            Raises:
                None: This method does not raise exceptions.
            """
            settings = self._state["settings"]
            return cast("dict[str, Any]", settings) if isinstance(settings, dict) else {}

        # History Management
        def add_to_session_history(self, action: str, details: dict[str, Any]) -> None:
            """Add an action to the session history.

            Args:
                action: Description of the action performed.
                details: Dictionary containing details about the action.

            Raises:
                None: This method does not raise exceptions.
            """
            entry: dict[str, Any] = {
                "action": action,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            }
            session_history = self._state["session_history"]
            if isinstance(session_history, list):
                session_history.append(entry)

                # Keep only last 1000 entries
                if len(session_history) > 1000:
                    self._state["session_history"] = session_history[-1000:]

        def get_session_history(self) -> list[dict[str, Any]]:
            """Get the session history.

            Returns:
                list[dict[str, Any]]: List of session history entries with action and
                    timestamp information.

            Raises:
                None: This method does not raise exceptions.
            """
            session_history = self._state["session_history"]
            return cast("list[dict[str, Any]]", session_history) if isinstance(session_history, list) else []

        def get_recent_files(self) -> list[str]:
            """Get list of recently opened files.

            Returns:
                list[str]: List of file paths ordered by most recent first (up to
                    10 entries).

            Raises:
                None: This method does not raise exceptions.
            """
            recent_files = self._state["recent_files"]
            return cast("list[str]", recent_files) if isinstance(recent_files, list) else []

        def get_recent_projects(self) -> list[str]:
            """Get list of recently opened projects.

            Returns:
                list[str]: List of project paths ordered by most recent first (up to
                    10 entries).

            Raises:
                None: This method does not raise exceptions.
            """
            recent_projects = self._state["recent_projects"]
            return cast("list[str]", recent_projects) if isinstance(recent_projects, list) else []

        def _get_timestamp(self) -> str:
            """Return a formatted timestamp string.

            Returns:
                str: ISO format timestamp string representing the current time.

            Raises:
                None: This method does not raise exceptions.
            """
            return datetime.now().isoformat()

        # Private helper methods
        def _add_to_recent_files(self, file_path: str) -> None:
            """Add a file to the recent files list.

            Args:
                file_path: Path to the file to add to recent files.

            Raises:
                None: This method does not raise exceptions.
            """
            recent_files = self._state["recent_files"]
            if isinstance(recent_files, list):
                if file_path in recent_files:
                    recent_files.remove(file_path)
                recent_files.insert(0, file_path)
                self._state["recent_files"] = recent_files[:10]

        def _add_to_recent_projects(self, project_path: str) -> None:
            """Add a project to the recent projects list.

            Args:
                project_path: Path to the project to add to recent projects.

            Raises:
                None: This method does not raise exceptions.
            """
            recent_projects = self._state["recent_projects"]
            if isinstance(recent_projects, list):
                if project_path in recent_projects:
                    recent_projects.remove(project_path)
                recent_projects.insert(0, project_path)
                self._state["recent_projects"] = recent_projects[:10]

        # State observation for debugging
        def get_full_state(self) -> dict[str, Any]:
            """Get the complete application state (for debugging).

            Returns:
                dict[str, Any]: Copy of the entire application state dictionary.

            Raises:
                None: This method does not raise exceptions.
            """
            return self._state.copy()

        def reset_state(self) -> None:
            """Reset the application state to defaults.

            Clears all active tasks, analysis results, and history while preserving
            settings configuration.

            Raises:
                None: This method does not raise exceptions.
            """
            logger.warning("Resetting application state")
            self.unload_binary()
            self.close_project()
            analysis_results = self._state["analysis_results"]
            if isinstance(analysis_results, dict):
                analysis_results.clear()
            active_tasks = self._state["active_tasks"]
            if isinstance(active_tasks, dict):
                active_tasks.clear()
            session_history = self._state["session_history"]
            if isinstance(session_history, list):
                session_history.clear()


# Global instance
_app_context_instance: AppContext | None = None


def get_app_context() -> AppContext:
    """Get the global AppContext instance.

    Returns a singleton instance of AppContext for managing application state
    across the entire Intellicrack application. The instance is created on first
    call and reused for subsequent calls.

    Returns:
        AppContext: The global AppContext singleton instance.

    Raises:
        None: This function does not raise exceptions.
    """
    global _app_context_instance
    if _app_context_instance is None:
        _app_context_instance = AppContext()
    return _app_context_instance
