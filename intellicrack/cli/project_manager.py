"""Project management CLI for Intellicrack.

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

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)
logger.debug("Project manager module loaded")


class ProjectManager:
    """Manage Intellicrack analysis projects."""

    def __init__(self) -> None:
        """Initialize project manager."""
        self.projects_dir = Path.home() / ".intellicrack" / "projects"
        logger.debug(f"Projects directory: {self.projects_dir}")
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.current_project = None

    def create_project(self, name: str, description: str = "") -> Path:
        """Create a new analysis project."""
        project_dir = self.projects_dir / name

        if project_dir.exists():
            raise ValueError(f"Project '{name}' already exists")

        project_dir.mkdir(parents=True)

        # Create project structure
        (project_dir / "binaries").mkdir()
        (project_dir / "analysis").mkdir()
        (project_dir / "reports").mkdir()
        (project_dir / "scripts").mkdir()
        (project_dir / "patches").mkdir()
        (project_dir / "logs").mkdir()

        # Create project metadata
        metadata = {
            "name": name,
            "description": description,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "files": [],
            "analyses": [],
            "version": "1.0.0",
        }

        with open(project_dir / "project.json", "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Created project: {name}")
        return project_dir

    def load_project(self, name: str) -> dict[str, Any]:
        """Load an existing project."""
        project_dir = self.projects_dir / name

        if not project_dir.exists():
            raise ValueError(f"Project '{name}' not found")

        with open(project_dir / "project.json") as f:
            metadata = json.load(f)

        self.current_project = {"name": name, "path": project_dir, "metadata": metadata}

        logger.info(f"Loaded project: {name}")
        return metadata

    def list_projects(self) -> list[dict[str, Any]]:
        """List all available projects."""
        projects = []

        for project_dir in self.projects_dir.iterdir():
            if project_dir.is_dir() and (project_dir / "project.json").exists():
                with open(project_dir / "project.json") as f:
                    metadata = json.load(f)
                    projects.append(
                        {
                            "name": metadata["name"],
                            "description": metadata.get("description", ""),
                            "created": metadata.get("created", ""),
                            "modified": metadata.get("modified", ""),
                            "path": str(project_dir),
                        },
                    )

        return projects

    def delete_project(self, name: str) -> None:
        """Delete a project and all its data."""
        project_dir = self.projects_dir / name

        if not project_dir.exists():
            raise ValueError(f"Project '{name}' not found")

        # Create backup before deletion
        backup_dir = self.projects_dir / "backups"
        backup_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{name}_{timestamp}.zip"

        # Create archive
        shutil.make_archive(str(backup_path.with_suffix("")), "zip", str(project_dir))

        # Delete project
        shutil.rmtree(project_dir)

        logger.info(f"Deleted project: {name} (backup: {backup_path})")

        if self.current_project and self.current_project["name"] == name:
            self.current_project = None

    def add_file_to_project(self, project_name: str, file_path: str) -> dict[str, Any]:
        """Add a binary file to project."""
        project_dir = self.projects_dir / project_name

        if not project_dir.exists():
            raise ValueError(f"Project '{project_name}' not found")

        source_file = Path(file_path)
        if not source_file.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Copy file to project
        dest_file = project_dir / "binaries" / source_file.name
        shutil.copy2(source_file, dest_file)

        # Update metadata
        with open(project_dir / "project.json") as f:
            metadata = json.load(f)

        file_info = {
            "name": source_file.name,
            "path": str(dest_file),
            "size": source_file.stat().st_size,
            "added": datetime.now().isoformat(),
            "hash": self._calculate_file_hash(source_file),
        }

        metadata["files"].append(file_info)
        metadata["modified"] = datetime.now().isoformat()

        with open(project_dir / "project.json", "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Added {source_file.name} to project {project_name}")
        return file_info

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        import hashlib

        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def export_project(self, project_name: str, output_path: str | None = None) -> Path:
        """Export project as archive."""
        project_dir = self.projects_dir / project_name

        if not project_dir.exists():
            raise ValueError(f"Project '{project_name}' not found")

        if output_path is None:
            output_path = Path.cwd() / f"{project_name}_export.zip"
        else:
            output_path = Path(output_path)

        # Create archive
        shutil.make_archive(str(output_path.with_suffix("")), "zip", str(project_dir))

        logger.info(f"Exported project to: {output_path}")
        return output_path

    def import_project(self, archive_path: str) -> str:
        """Import project from archive."""
        archive_path = Path(archive_path)

        if not archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        # Extract to temporary location
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            shutil.unpack_archive(archive_path, temp_dir)

            # Find project.json
            project_json = None
            for root, _dirs, files in os.walk(temp_dir):
                if "project.json" in files:
                    project_json = Path(root) / "project.json"
                    break

            if not project_json:
                raise ValueError("Invalid project archive: missing project.json")

            # Read metadata
            with open(project_json) as f:
                metadata = json.load(f)

            project_name = metadata["name"]

            # Check if project already exists
            dest_dir = self.projects_dir / project_name
            if dest_dir.exists():
                # Create unique name
                counter = 1
                while dest_dir.exists():
                    project_name = f"{metadata['name']}_{counter}"
                    dest_dir = self.projects_dir / project_name
                    counter += 1

                # Update metadata
                metadata["name"] = project_name
                with open(project_json, "w") as f:
                    json.dump(metadata, f, indent=2)

            # Copy to projects directory
            shutil.copytree(project_json.parent, dest_dir)

        logger.info(f"Imported project: {project_name}")
        return project_name


def main() -> int:
    """Project management CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="Intellicrack Project Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Create project
    create_parser = subparsers.add_parser("create", help="Create new project")
    create_parser.add_argument("name", help="Project name")
    create_parser.add_argument("-d", "--description", default="", help="Project description")

    # List projects
    subparsers.add_parser("list", help="List all projects")

    # Load project
    load_parser = subparsers.add_parser("load", help="Load project")
    load_parser.add_argument("name", help="Project name")

    # Delete project
    delete_parser = subparsers.add_parser("delete", help="Delete project")
    delete_parser.add_argument("name", help="Project name")
    delete_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Add file
    add_parser = subparsers.add_parser("add", help="Add file to project")
    add_parser.add_argument("project", help="Project name")
    add_parser.add_argument("file", help="File path")

    # Export project
    export_parser = subparsers.add_parser("export", help="Export project")
    export_parser.add_argument("name", help="Project name")
    export_parser.add_argument("-o", "--output", help="Output path")

    # Import project
    import_parser = subparsers.add_parser("import", help="Import project")
    import_parser.add_argument("archive", help="Archive path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    manager = ProjectManager()

    try:
        if args.command == "create":
            manager.create_project(args.name, args.description)
            print(f"Created project: {args.name}")

        elif args.command == "list":
            projects = manager.list_projects()
            if not projects:
                print("No projects found")
            else:
                print("\nAvailable projects:")
                for proj in projects:
                    print(f"  - {proj['name']}: {proj['description']}")
                    print(f"    Created: {proj['created']}")
                    print(f"    Modified: {proj['modified']}")

        elif args.command == "load":
            metadata = manager.load_project(args.name)
            print(f"Loaded project: {metadata['name']}")
            print(f"Description: {metadata.get('description', 'N/A')}")
            print(f"Files: {len(metadata.get('files', []))}")

        elif args.command == "delete":
            if not args.force:
                response = input(f"Delete project '{args.name}'? (y/N): ")
                if response.lower() != "y":
                    print("Cancelled")
                    return 0

            manager.delete_project(args.name)
            print(f"Deleted project: {args.name}")

        elif args.command == "add":
            file_info = manager.add_file_to_project(args.project, args.file)
            print(f"Added {file_info['name']} to project {args.project}")

        elif args.command == "export":
            output_path = manager.export_project(args.name, args.output)
            print(f"Exported to: {output_path}")

        elif args.command == "import":
            project_name = manager.import_project(args.archive)
            print(f"Imported project: {project_name}")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
