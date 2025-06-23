#!/usr/bin/env python3
"""
Project Management - CLI workspace and project support for Intellicrack

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

import glob
import json
import os
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Optional imports for enhanced project management
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class IntellicrackProject:
    """Represents an Intellicrack analysis project."""

    def __init__(self, name: str, path: str, description: str = ""):
        """Initialize project.

        Args:
            name: Project name
            path: Project directory path
            description: Project description
        """
        self.name = name
        self.path = path
        self.description = description
        self.created_time = datetime.now()
        self.modified_time = datetime.now()

        # Project structure
        self.binaries = []
        self.analysis_results = {}
        self.scripts = []
        self.reports = []
        self.notes = ""
        self.tags = []

        # Project settings
        self.settings = {
            'auto_save': True,
            'backup_enabled': True,
            'analysis_timeout': 300,
            'export_format': 'json',
            'temp_cleanup': True
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert project to dictionary."""
        return {
            'name': self.name,
            'path': self.path,
            'description': self.description,
            'created_time': self.created_time.isoformat(),
            'modified_time': self.modified_time.isoformat(),
            'binaries': self.binaries,
            'analysis_results': self.analysis_results,
            'scripts': self.scripts,
            'reports': self.reports,
            'notes': self.notes,
            'tags': self.tags,
            'settings': self.settings
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntellicrackProject':
        """Create project from dictionary."""
        project = cls(
            data['name'],
            data['path'],
            data.get('description', '')
        )

        project.created_time = datetime.fromisoformat(data.get('created_time', datetime.now().isoformat()))
        project.modified_time = datetime.fromisoformat(data.get('modified_time', datetime.now().isoformat()))
        project.binaries = data.get('binaries', [])
        project.analysis_results = data.get('analysis_results', {})
        project.scripts = data.get('scripts', [])
        project.reports = data.get('reports', [])
        project.notes = data.get('notes', '')
        project.tags = data.get('tags', [])
        project.settings = data.get('settings', project.settings)

        return project

    def add_binary(self, binary_path: str) -> bool:
        """Add binary to project."""
        if os.path.exists(binary_path):
            rel_path = os.path.relpath(binary_path, self.path)
            if rel_path not in self.binaries:
                self.binaries.append(rel_path)
                self.modified_time = datetime.now()
                return True
        return False

    def remove_binary(self, binary_path: str) -> bool:
        """Remove binary from project."""
        rel_path = os.path.relpath(binary_path, self.path)
        if rel_path in self.binaries:
            self.binaries.remove(rel_path)
            self.modified_time = datetime.now()
            return True
        return False

    def add_analysis_result(self, binary_name: str, analysis_data: Dict[str, Any]) -> None:
        """Add analysis result for a binary."""
        self.analysis_results[binary_name] = {
            'timestamp': datetime.now().isoformat(),
            'data': analysis_data
        }
        self.modified_time = datetime.now()

    def get_project_size(self) -> int:
        """Get total project size in bytes."""
        total_size = 0
        try:
            for root, dirs, files in os.walk(self.path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
        except OSError:
            pass
        return total_size

    def get_binary_count(self) -> int:
        """Get number of binaries in project."""
        return len(self.binaries)

    def get_analysis_count(self) -> int:
        """Get number of analysis results."""
        return len(self.analysis_results)


class ProjectManager:
    """Manages Intellicrack projects and workspaces."""

    def __init__(self, workspace_root: str = ".intellicrack"):
        """Initialize project manager.

        Args:
            workspace_root: Root directory for workspaces
        """
        self.workspace_root = os.path.expanduser(f"~/{workspace_root}")
        self.projects_dir = os.path.join(self.workspace_root, "projects")
        self.templates_dir = os.path.join(self.workspace_root, "templates")
        self.config_file = os.path.join(self.workspace_root, "config.json")

        self.console = Console() if RICH_AVAILABLE else None
        self.current_project = None

        # Manager settings
        self.settings = {
            'auto_backup': True,
            'max_projects': 50,
            'cleanup_old_projects': True,
            'compression_enabled': True
        }

        self._ensure_workspace_structure()
        self._load_config()

    def _ensure_workspace_structure(self):
        """Ensure workspace directory structure exists."""
        directories = [
            self.workspace_root,
            self.projects_dir,
            self.templates_dir,
            os.path.join(self.workspace_root, "backups"),
            os.path.join(self.workspace_root, "temp")
        ]

        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def _load_config(self):
        """Load manager configuration."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.settings.update(config.get('manager_settings', {}))
        except Exception:
            pass

    def _save_config(self):
        """Save manager configuration."""
        try:
            config = {
                'manager_settings': self.settings,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def create_project(self, name: str, description: str = "",
                      template: Optional[str] = None) -> Optional[IntellicrackProject]:
        """Create new project.

        Args:
            name: Project name
            description: Project description
            template: Optional template name

        Returns:
            Created project or None if failed
        """
        # Validate project name
        if not name or not name.isalnum():
            return None

        project_path = os.path.join(self.projects_dir, name)

        if os.path.exists(project_path):
            return None  # Project already exists

        try:
            # Create project directory
            os.makedirs(project_path, exist_ok=True)

            # Create project structure
            subdirs = ['binaries', 'results', 'scripts', 'reports', 'temp']
            for subdir in subdirs:
                os.makedirs(os.path.join(project_path, subdir), exist_ok=True)

            # Create project
            project = IntellicrackProject(name, project_path, description)

            # Apply template if specified
            if template:
                self._apply_template(project, template)

            # Save project
            self._save_project(project)

            return project

        except Exception:
            # Cleanup on failure
            if os.path.exists(project_path):
                shutil.rmtree(project_path, ignore_errors=True)
            return None

    def load_project(self, name: str) -> Optional[IntellicrackProject]:
        """Load existing project.

        Args:
            name: Project name

        Returns:
            Loaded project or None if not found
        """
        project_path = os.path.join(self.projects_dir, name)
        project_file = os.path.join(project_path, "project.json")

        if not os.path.exists(project_file):
            return None

        try:
            with open(project_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            project = IntellicrackProject.from_dict(data)
            self.current_project = project
            return project

        except Exception:
            return None

    def save_project(self, project: IntellicrackProject) -> bool:
        """Save project to disk.

        Args:
            project: Project to save

        Returns:
            True if successful
        """
        return self._save_project(project)

    def _save_project(self, project: IntellicrackProject) -> bool:
        """Internal project save method."""
        try:
            project_file = os.path.join(project.path, "project.json")

            # Create backup if enabled
            if self.settings['auto_backup'] and os.path.exists(project_file):
                self._backup_project(project)

            # Save project data
            with open(project_file, 'w', encoding='utf-8') as f:
                json.dump(project.to_dict(), f, indent=2)

            return True

        except Exception:
            return False

    def delete_project(self, name: str) -> bool:
        """Delete project.

        Args:
            name: Project name

        Returns:
            True if successful
        """
        project_path = os.path.join(self.projects_dir, name)

        if not os.path.exists(project_path):
            return False

        try:
            # Create final backup
            project = self.load_project(name)
            if project and self.settings['auto_backup']:
                self._backup_project(project)

            # Delete project directory
            shutil.rmtree(project_path)

            if self.current_project and self.current_project.name == name:
                self.current_project = None

            return True

        except Exception:
            return False

    def list_projects(self) -> List[Dict[str, Any]]:
        """List all projects.

        Returns:
            List of project information dictionaries
        """
        projects = []

        try:
            for project_dir in os.listdir(self.projects_dir):
                project_path = os.path.join(self.projects_dir, project_dir)
                project_file = os.path.join(project_path, "project.json")

                if os.path.isdir(project_path) and os.path.exists(project_file):
                    try:
                        with open(project_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)

                        # Calculate project size
                        size = self._get_directory_size(project_path)

                        projects.append({
                            'name': data['name'],
                            'description': data.get('description', ''),
                            'created_time': data.get('created_time', ''),
                            'modified_time': data.get('modified_time', ''),
                            'size': size,
                            'binary_count': len(data.get('binaries', [])),
                            'analysis_count': len(data.get('analysis_results', {}))
                        })

                    except Exception:
                        continue

        except Exception:
            pass

        return sorted(projects, key=lambda x: x['modified_time'], reverse=True)

    def import_binary(self, project: IntellicrackProject, binary_path: str,
                     copy_file: bool = True) -> bool:
        """Import binary into project.

        Args:
            project: Target project
            binary_path: Path to binary file
            copy_file: Whether to copy file into project

        Returns:
            True if successful
        """
        if not os.path.exists(binary_path):
            return False

        try:
            if copy_file:
                # Copy binary to project binaries directory
                binary_name = os.path.basename(binary_path)
                target_path = os.path.join(project.path, "binaries", binary_name)

                # Handle duplicate names
                counter = 1
                while os.path.exists(target_path):
                    name, ext = os.path.splitext(binary_name)
                    target_path = os.path.join(project.path, "binaries", f"{name}_{counter}{ext}")
                    counter += 1

                shutil.copy2(binary_path, target_path)
                project.add_binary(target_path)
            else:
                # Just add reference
                project.add_binary(binary_path)

            return self._save_project(project)

        except Exception:
            return False

    def export_project(self, project: IntellicrackProject, export_path: str,
                      include_binaries: bool = True) -> bool:
        """Export project to archive.

        Args:
            project: Project to export
            export_path: Export file path
            include_binaries: Whether to include binary files

        Returns:
            True if successful
        """
        try:
            import zipfile

            with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add project metadata
                project_data = project.to_dict()
                zipf.writestr("project.json", json.dumps(project_data, indent=2))

                # Add project files
                for root, dirs, files in os.walk(project.path):
                    for file in files:
                        file_path = os.path.join(root, file)

                        # Skip binaries if not requested
                        if not include_binaries and "binaries" in file_path:
                            continue

                        # Skip temp files
                        if "temp" in file_path:
                            continue

                        arc_path = os.path.relpath(file_path, project.path)
                        zipf.write(file_path, arc_path)

            return True

        except Exception:
            return False

    def import_project(self, archive_path: str, project_name: Optional[str] = None) -> Optional[IntellicrackProject]:
        """Import project from archive.

        Args:
            archive_path: Path to project archive
            project_name: Optional new project name

        Returns:
            Imported project or None if failed
        """
        if not os.path.exists(archive_path):
            return None

        try:
            import zipfile

            with zipfile.ZipFile(archive_path, 'r') as zipf:
                # Read project metadata
                project_data = json.loads(zipf.read("project.json").decode('utf-8'))

                # Use provided name or original name
                name = project_name or project_data['name']

                # Create new project
                project = self.create_project(name, project_data.get('description', ''))
                if not project:
                    return None

                # Extract files
                zipf.extractall(project.path)

                # Update project with imported data
                imported_project = IntellicrackProject.from_dict(project_data)
                imported_project.name = name
                imported_project.path = project.path

                # Save updated project
                self._save_project(imported_project)

                return imported_project

        except Exception:
            return None

    def _apply_template(self, project: IntellicrackProject, template_name: str):
        """Apply template to project."""
        template_path = os.path.join(self.templates_dir, f"{template_name}.json")

        if os.path.exists(template_path):
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    template_data = json.load(f)

                # Apply template settings
                project.settings.update(template_data.get('settings', {}))
                project.tags.extend(template_data.get('tags', []))
                project.notes = template_data.get('notes', '')

                # Create template files
                for file_info in template_data.get('files', []):
                    file_path = os.path.join(project.path, file_info['path'])
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)

                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(file_info.get('content', ''))

            except Exception:
                pass

    def _backup_project(self, project: IntellicrackProject):
        """Create project backup."""
        try:
            backup_dir = os.path.join(self.workspace_root, "backups")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{project.name}_{timestamp}.zip"
            backup_path = os.path.join(backup_dir, backup_name)

            self.export_project(project, backup_path, include_binaries=False)

            # Cleanup old backups (keep last 5)
            backups = glob.glob(os.path.join(backup_dir, f"{project.name}_*.zip"))
            backups.sort()

            if len(backups) > 5:
                for old_backup in backups[:-5]:
                    try:
                        os.remove(old_backup)
                    except OSError:
                        pass

        except Exception:
            pass

    def _get_directory_size(self, path: str) -> int:
        """Get directory size in bytes."""
        total_size = 0
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
        except OSError:
            pass
        return total_size

    def display_projects_table(self) -> None:
        """Display projects in a formatted table."""
        projects = self.list_projects()

        if not projects:
            if self.console:
                self.console.print("[yellow]No projects found[/yellow]")
            else:
                print("No projects found")
            return

        if self.console:
            table = Table(title="Intellicrack Projects")
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="yellow")
            table.add_column("Binaries", style="green", justify="right")
            table.add_column("Analysis", style="blue", justify="right")
            table.add_column("Size", style="magenta", justify="right")
            table.add_column("Modified", style="dim")

            for project in projects:
                size_mb = project['size'] / (1024 * 1024)
                size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{project['size']} bytes"

                modified_time = datetime.fromisoformat(project['modified_time'])
                modified_str = modified_time.strftime("%Y-%m-%d %H:%M")

                table.add_row(
                    project['name'],
                    project['description'][:30] + "..." if len(project['description']) > 30 else project['description'],
                    str(project['binary_count']),
                    str(project['analysis_count']),
                    size_str,
                    modified_str
                )

            self.console.print(table)
        else:
            print("\\nInteLLicrack Projects:")
            print("-" * 80)
            print(f"{'Name':<15} {'Binaries':<8} {'Analysis':<8} {'Size':<10} {'Modified':<16}")
            print("-" * 80)

            for project in projects:
                size_mb = project['size'] / (1024 * 1024)
                size_str = f"{size_mb:.1f}MB" if size_mb >= 1 else f"{project['size']}B"

                modified_time = datetime.fromisoformat(project['modified_time'])
                modified_str = modified_time.strftime("%m-%d %H:%M")

                print(f"{project['name']:<15} {project['binary_count']:<8} {project['analysis_count']:<8} "
                      f"{size_str:<10} {modified_str:<16}")
            print()

    def cleanup_workspace(self) -> int:
        """Clean up workspace (temp files, old backups, etc.).

        Returns:
            Number of files cleaned up
        """
        cleaned_count = 0

        try:
            # Clean temp directories
            temp_dir = os.path.join(self.workspace_root, "temp")
            if os.path.exists(temp_dir):
                for item in os.listdir(temp_dir):
                    item_path = os.path.join(temp_dir, item)
                    try:
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                            cleaned_count += 1
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                            cleaned_count += 1
                    except OSError:
                        pass

            # Clean old backups (older than 30 days)
            backup_dir = os.path.join(self.workspace_root, "backups")
            if os.path.exists(backup_dir):
                cutoff_time = time.time() - (30 * 24 * 60 * 60)  # 30 days

                for backup_file in os.listdir(backup_dir):
                    backup_path = os.path.join(backup_dir, backup_file)
                    try:
                        if os.path.getmtime(backup_path) < cutoff_time:
                            os.remove(backup_path)
                            cleaned_count += 1
                    except OSError:
                        pass

        except Exception:
            pass

        return cleaned_count


# Convenience functions
def get_project_manager() -> ProjectManager:
    """Get default project manager instance."""
    return ProjectManager()


def format_size(size_bytes: int) -> str:
    """Format size in bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


if __name__ == "__main__":
    # Test project management
    manager = ProjectManager()

    # Create test project
    project = manager.create_project("test_project", "Test project for development")
    if project:
        print(f"Created project: {project.name}")
        manager.display_projects_table()
    else:
        print("Failed to create project")
