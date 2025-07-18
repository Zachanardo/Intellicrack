"""Application context management for Intellicrack.

This module provides centralized application context management including
configuration, state management, and shared resources across the application.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from intellicrack.logger import get_logger

logger = get_logger(__name__)


class AppContext(QObject):
    """
    Centralized application state manager.
    
    Manages global application state and provides signals for state changes,
    enabling decoupled communication between UI components.
    """

    # State change signals
    binary_loaded = pyqtSignal(dict)  # Emitted when a binary is loaded
    binary_unloaded = pyqtSignal()  # Emitted when binary is unloaded
    analysis_started = pyqtSignal(str, dict)  # analysis_type, options
    analysis_completed = pyqtSignal(str, dict)  # analysis_type, results
    analysis_failed = pyqtSignal(str, str)  # analysis_type, error_message
    project_loaded = pyqtSignal(dict)  # project_info
    project_saved = pyqtSignal(str)  # project_path
    project_closed = pyqtSignal()
    plugin_loaded = pyqtSignal(str, dict)  # plugin_name, plugin_info
    plugin_unloaded = pyqtSignal(str)  # plugin_name
    settings_changed = pyqtSignal(str, Any)  # setting_key, new_value
    task_started = pyqtSignal(str, str)  # task_id, task_description
    task_progress = pyqtSignal(str, int)  # task_id, progress_percentage
    task_completed = pyqtSignal(str, Any)  # task_id, result
    task_failed = pyqtSignal(str, str)  # task_id, error_message
    model_loaded = pyqtSignal(str, dict)  # model_name, model_info
    model_unloaded = pyqtSignal(str)  # model_name

    def __init__(self):
        """Initialize the application context.
        
        Sets up the application context with state management for binaries,
        projects, analysis results, plugins, models, settings, and active
        tasks. Initializes signal-slot connections and observer patterns
        for communication between different components of the application.
        """
        super().__init__()
        self._state = {
            'current_binary': None,
            'current_project': None,
            'analysis_results': {},
            'loaded_plugins': {},
            'loaded_models': {},
            'settings': {},
            'active_tasks': {},
            'session_history': [],
            'recent_files': [],
            'recent_projects': []
        }
        self._observers = {}
        logger.info("AppContext initialized")

    # Binary Management
    def load_binary(self, file_path: str, metadata: Optional[Dict] = None) -> bool:
        """Load a binary file and emit appropriate signals."""
        try:
            path = Path(file_path)
            if not path.exists():
                logger.error(f"Binary file not found: {file_path}")
                return False

            binary_info = {
                'path': str(path.absolute()),
                'name': path.name,
                'size': path.stat().st_size,
                'loaded_at': datetime.now().isoformat(),
                'metadata': metadata or {}
            }

            self._state['current_binary'] = binary_info
            self._add_to_recent_files(str(path.absolute()))

            logger.info(f"Binary loaded: {path.name}")
            self.binary_loaded.emit(binary_info)
            return True

        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False

    def unload_binary(self):
        """Unload the current binary."""
        if self._state['current_binary']:
            logger.info(f"Unloading binary: {self._state['current_binary']['name']}")
            self._state['current_binary'] = None
            self._state['analysis_results'].clear()
            self.binary_unloaded.emit()

    def get_current_binary(self) -> Optional[Dict]:
        """Get information about the currently loaded binary."""
        return self._state['current_binary']

    # Analysis Results Management
    def set_analysis_results(self, analysis_type: str, results: Dict):
        """Store analysis results and emit completion signal."""
        self._state['analysis_results'][analysis_type] = {
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        logger.info(f"Analysis completed: {analysis_type}")
        self.analysis_completed.emit(analysis_type, results)

    def get_analysis_results(self, analysis_type: Optional[str] = None) -> Dict:
        """Get analysis results for a specific type or all results."""
        if analysis_type:
            return self._state['analysis_results'].get(analysis_type, {})
        return self._state['analysis_results']

    def start_analysis(self, analysis_type: str, options: Optional[Dict] = None):
        """Signal that an analysis has started."""
        logger.info(f"Analysis started: {analysis_type}")
        self.analysis_started.emit(analysis_type, options or {})

    def fail_analysis(self, analysis_type: str, error_message: str):
        """Signal that an analysis has failed."""
        logger.error(f"Analysis failed: {analysis_type} - {error_message}")
        self.analysis_failed.emit(analysis_type, error_message)

    # Project Management
    def load_project(self, project_path: str) -> bool:
        """Load a project from file."""
        try:
            path = Path(project_path)
            if not path.exists():
                logger.error(f"Project file not found: {project_path}")
                return False

            with open(path, 'r') as f:
                project_data = json.load(f)

            project_info = {
                'path': str(path.absolute()),
                'name': project_data.get('name', path.stem),
                'data': project_data,
                'loaded_at': datetime.now().isoformat()
            }

            self._state['current_project'] = project_info
            self._add_to_recent_projects(str(path.absolute()))

            # Load associated binary if specified
            if 'binary_path' in project_data:
                self.load_binary(project_data['binary_path'])

            # Restore analysis results if present
            if 'analysis_results' in project_data:
                self._state['analysis_results'] = project_data['analysis_results']

            logger.info(f"Project loaded: {project_info['name']}")
            self.project_loaded.emit(project_info)
            return True

        except Exception as e:
            logger.error(f"Failed to load project: {e}")
            return False

    def save_project(self, project_path: str) -> bool:
        """Save current state as a project."""
        try:
            project_data = {
                'name': Path(project_path).stem,
                'created_at': datetime.now().isoformat(),
                'binary_path': self._state['current_binary']['path'] if self._state['current_binary'] else None,
                'analysis_results': self._state['analysis_results'],
                'settings': self._state['settings']
            }

            path = Path(project_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(project_data, f, indent=2)

            self._state['current_project'] = {
                'path': str(path.absolute()),
                'name': project_data['name'],
                'data': project_data
            }

            logger.info(f"Project saved: {project_path}")
            self.project_saved.emit(str(path.absolute()))
            return True

        except Exception as e:
            logger.error(f"Failed to save project: {e}")
            return False

    def close_project(self):
        """Close the current project."""
        if self._state['current_project']:
            logger.info(f"Closing project: {self._state['current_project']['name']}")
            self._state['current_project'] = None
            self.project_closed.emit()

    # Plugin Management
    def register_plugin(self, plugin_name: str, plugin_info: Dict):
        """Register a loaded plugin."""
        self._state['loaded_plugins'][plugin_name] = {
            'info': plugin_info,
            'loaded_at': datetime.now().isoformat()
        }
        logger.info(f"Plugin registered: {plugin_name}")
        self.plugin_loaded.emit(plugin_name, plugin_info)

    def unregister_plugin(self, plugin_name: str):
        """Unregister a plugin."""
        if plugin_name in self._state['loaded_plugins']:
            del self._state['loaded_plugins'][plugin_name]
            logger.info(f"Plugin unregistered: {plugin_name}")
            self.plugin_unloaded.emit(plugin_name)

    def get_loaded_plugins(self) -> Dict:
        """Get information about all loaded plugins."""
        return self._state['loaded_plugins']

    # Model Management
    def register_model(self, model_name: str, model_info: Dict):
        """Register a loaded AI model."""
        self._state['loaded_models'][model_name] = {
            'info': model_info,
            'loaded_at': datetime.now().isoformat()
        }
        logger.info(f"Model registered: {model_name}")
        self.model_loaded.emit(model_name, model_info)

    def unregister_model(self, model_name: str):
        """Unregister an AI model."""
        if model_name in self._state['loaded_models']:
            del self._state['loaded_models'][model_name]
            logger.info(f"Model unregistered: {model_name}")
            self.model_unloaded.emit(model_name)

    def get_loaded_models(self) -> Dict:
        """Get information about all loaded models."""
        return self._state['loaded_models']

    # Task Management
    def register_task(self, task_id: str, description: str):
        """Register a new task."""
        self._state['active_tasks'][task_id] = {
            'description': description,
            'started_at': datetime.now().isoformat(),
            'progress': 0
        }
        logger.info(f"Task registered: {task_id} - {description}")
        self.task_started.emit(task_id, description)

    def update_task_progress(self, task_id: str, progress: int):
        """Update task progress."""
        if task_id in self._state['active_tasks']:
            self._state['active_tasks'][task_id]['progress'] = progress
            self.task_progress.emit(task_id, progress)

    def complete_task(self, task_id: str, result: Any = None):
        """Mark a task as completed."""
        if task_id in self._state['active_tasks']:
            task_info = self._state['active_tasks'].pop(task_id)
            logger.info(f"Task completed: {task_id} - {task_info['description']}")
            self.task_completed.emit(task_id, result)

    def fail_task(self, task_id: str, error_message: str):
        """Mark a task as failed."""
        if task_id in self._state['active_tasks']:
            task_info = self._state['active_tasks'].pop(task_id)

            # Store failed task information
            failed_task = {
                'task_id': task_id,
                'original_info': task_info,
                'error_message': error_message,
                'failed_at': self._get_timestamp()
            }

            if 'failed_tasks' not in self._state:
                self._state['failed_tasks'] = []
            self._state['failed_tasks'].append(failed_task)

            logger.error(f"Task failed: {task_id} ({task_info.get('description', 'N/A')}) - {error_message}")
            self.task_failed.emit(task_id, error_message)

    def get_active_tasks(self) -> Dict:
        """Get all active tasks."""
        return self._state['active_tasks']

    # Settings Management
    def set_setting(self, key: str, value: Any):
        """Update a setting value."""
        old_value = self._state['settings'].get(key)
        self._state['settings'][key] = value

        if old_value != value:
            logger.info(f"Setting changed: {key} = {value} (was: {old_value})")
        else:
            logger.debug(f"Setting updated (no change): {key} = {value}")

        self.settings_changed.emit(key, value)

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        return self._state['settings'].get(key, default)

    def get_all_settings(self) -> Dict:
        """Get all settings."""
        return self._state['settings']

    # History Management
    def add_to_session_history(self, action: str, details: Dict):
        """Add an action to the session history."""
        entry = {
            'action': action,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self._state['session_history'].append(entry)

        # Keep only last 1000 entries
        if len(self._state['session_history']) > 1000:
            self._state['session_history'] = self._state['session_history'][-1000:]

    def get_session_history(self) -> List[Dict]:
        """Get the session history."""
        return self._state['session_history']

    def get_recent_files(self) -> List[str]:
        """Get list of recently opened files."""
        return self._state['recent_files']

    def get_recent_projects(self) -> List[str]:
        """Get list of recently opened projects."""
        return self._state['recent_projects']

    # Private helper methods
    def _add_to_recent_files(self, file_path: str):
        """Add a file to the recent files list."""
        if file_path in self._state['recent_files']:
            self._state['recent_files'].remove(file_path)
        self._state['recent_files'].insert(0, file_path)
        self._state['recent_files'] = self._state['recent_files'][:10]  # Keep last 10

    def _add_to_recent_projects(self, project_path: str):
        """Add a project to the recent projects list."""
        if project_path in self._state['recent_projects']:
            self._state['recent_projects'].remove(project_path)
        self._state['recent_projects'].insert(0, project_path)
        self._state['recent_projects'] = self._state['recent_projects'][:10]  # Keep last 10

    # State observation for debugging
    def get_full_state(self) -> Dict:
        """Get the complete application state (for debugging)."""
        return self._state.copy()

    def reset_state(self):
        """Reset the application state to defaults."""
        logger.warning("Resetting application state")
        self.unload_binary()
        self.close_project()
        self._state['analysis_results'].clear()
        self._state['active_tasks'].clear()
        self._state['session_history'].clear()


# Global instance
_app_context_instance = None


def get_app_context() -> AppContext:
    """Get the global AppContext instance."""
    global _app_context_instance
    if _app_context_instance is None:
        _app_context_instance = AppContext()
    return _app_context_instance
