"""Ghidra Project Management System.

Production-ready project management for persistent Ghidra analysis storage,
versioning, binary diffing, and collaborative features.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import difflib
import hashlib
import json
import os
import sqlite3
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import lz4.frame
import msgpack

from intellicrack.core.analysis.ghidra_analyzer import GhidraAnalysisResult, GhidraDataType, GhidraFunction


@dataclass
class ProjectVersion:
    """Represents a versioned state of a project."""

    version_id: str
    timestamp: datetime
    binary_hash: str
    analysis_data: bytes  # Compressed analysis result
    metadata: dict[str, Any]
    parent_version: str | None = None
    author: str = "intellicrack"
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class GhidraProject:
    """Represents a persistent Ghidra analysis project."""

    project_id: str
    name: str
    binary_path: str
    created_at: datetime
    modified_at: datetime
    versions: list[ProjectVersion]
    current_version: str
    collaborators: list[str]
    settings: dict[str, Any]
    is_locked: bool = False


class GhidraProjectManager:
    """Manages persistent Ghidra projects with versioning and collaboration."""

    def __init__(self, projects_dir: str | None = None) -> None:
        """Initialize the GhidraProjectManager with an optional projects directory."""
        self.projects_dir = Path(projects_dir) if projects_dir else Path.home() / ".intellicrack" / "ghidra_projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.projects_dir / "projects.db"
        self._init_database()
        self._init_cache()

    def _init_database(self) -> None:
        """Initialize SQLite database for project metadata."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                binary_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                modified_at TIMESTAMP NOT NULL,
                current_version TEXT NOT NULL,
                is_locked INTEGER DEFAULT 0,
                settings TEXT,
                metadata TEXT
            )
        """)

        # Versions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS versions (
                version_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                binary_hash TEXT NOT NULL,
                parent_version TEXT,
                author TEXT NOT NULL,
                description TEXT,
                tags TEXT,
                data_path TEXT NOT NULL,
                data_size INTEGER NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(project_id)
            )
        """)

        # Collaborators table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaborators (
                project_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                added_at TIMESTAMP NOT NULL,
                PRIMARY KEY (project_id, user_id),
                FOREIGN KEY (project_id) REFERENCES projects(project_id)
            )
        """)

        # Analysis cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_cache (
                cache_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                function_address INTEGER NOT NULL,
                cache_type TEXT NOT NULL,
                cache_data BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(project_id),
                FOREIGN KEY (version_id) REFERENCES versions(version_id)
            )
        """)

        conn.commit()
        conn.close()

    def _init_cache(self) -> None:
        """Initialize in-memory cache for frequently accessed data."""
        self.cache: dict[str, dict[str, Any]] = {"projects": {}, "versions": {}, "analysis_results": {}}

    def create_project(self, name: str, binary_path: str, initial_analysis: GhidraAnalysisResult | None = None) -> GhidraProject:
        """Create a new Ghidra project with initial version."""
        project_id = self._generate_project_id(name, binary_path)
        binary_hash = self._compute_file_hash(binary_path)

        # Create project directory
        project_dir = self.projects_dir / project_id
        project_dir.mkdir(exist_ok=True)

        # Create initial version
        version_id = self._generate_version_id()
        timestamp = datetime.now()

        # Save initial analysis if provided
        if initial_analysis:
            analysis_data = self._compress_analysis(initial_analysis)
            version_path = project_dir / f"version_{version_id}.dat"
            with open(version_path, "wb") as f:
                f.write(analysis_data)
        else:
            analysis_data = b""
            version_path = project_dir / f"version_{version_id}.dat"
            version_path.touch()

        # Create version record
        version = ProjectVersion(
            version_id=version_id,
            timestamp=timestamp,
            binary_hash=binary_hash,
            analysis_data=analysis_data,
            metadata={"initial": True},
            description="Initial project creation",
        )

        # Create project record
        project = GhidraProject(
            project_id=project_id,
            name=name,
            binary_path=binary_path,
            created_at=timestamp,
            modified_at=timestamp,
            versions=[version],
            current_version=version_id,
            collaborators=[],
            settings={},
        )

        # Store in database
        self._save_project_to_db(project)
        self._save_version_to_db(project_id, version, str(version_path))

        # Cache the project
        self.cache["projects"][project_id] = project

        return project

    def load_project(self, project_id: str) -> GhidraProject | None:
        """Load a project from persistent storage."""
        # Check cache first
        if project_id in self.cache["projects"]:
            cached_project = self.cache["projects"][project_id]
            if isinstance(cached_project, GhidraProject):
                return cached_project

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Load project metadata
        cursor.execute(
            """
            SELECT name, binary_path, created_at, modified_at, current_version,
                   is_locked, settings, metadata
            FROM projects WHERE project_id = ?
        """,
            (project_id,),
        )

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        name: str = row[0]
        binary_path: str = row[1]
        created_at: str = row[2]
        modified_at: str = row[3]
        current_version: str = row[4]
        is_locked: int = row[5]
        settings_json: str | None = row[6]
        metadata_json: str | None = row[7]

        # Load versions
        cursor.execute(
            """
            SELECT version_id, timestamp, binary_hash, parent_version,
                   author, description, tags, data_path
            FROM versions WHERE project_id = ?
            ORDER BY timestamp
        """,
            (project_id,),
        )

        versions = []
        for version_row in cursor.fetchall():
            version = ProjectVersion(
                version_id=version_row[0],
                timestamp=datetime.fromisoformat(version_row[1]),
                binary_hash=version_row[2],
                analysis_data=b"",  # Loaded on demand
                metadata={},
                parent_version=version_row[3],
                author=version_row[4],
                description=version_row[5],
                tags=json.loads(version_row[6]) if version_row[6] else [],
            )
            versions.append(version)

        # Load collaborators
        cursor.execute(
            """
            SELECT user_id FROM collaborators WHERE project_id = ?
        """,
            (project_id,),
        )
        collaborators = [row[0] for row in cursor.fetchall()]

        conn.close()

        # Create project object
        project = GhidraProject(
            project_id=project_id,
            name=name,
            binary_path=binary_path,
            created_at=datetime.fromisoformat(created_at),
            modified_at=datetime.fromisoformat(modified_at),
            versions=versions,
            current_version=current_version,
            collaborators=collaborators,
            settings=json.loads(settings_json) if settings_json else {},
            is_locked=bool(is_locked),
        )

        # Cache the project
        self.cache["projects"][project_id] = project

        return project

    def save_version(
        self,
        project_id: str,
        analysis_result: GhidraAnalysisResult,
        description: str = "",
        tags: list[str] | None = None,
    ) -> ProjectVersion:
        """Save a new version of the project."""
        project = self.load_project(project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        if project.is_locked:
            raise ValueError(f"Project {project_id} is locked")

        # Create new version
        version_id = self._generate_version_id()
        binary_hash = self._compute_file_hash(project.binary_path)
        analysis_data = self._compress_analysis(analysis_result)

        # Save version data
        project_dir = self.projects_dir / project_id
        version_path = project_dir / f"version_{version_id}.dat"
        with open(version_path, "wb") as f:
            f.write(analysis_data)

        # Create version record
        version = ProjectVersion(
            version_id=version_id,
            timestamp=datetime.now(),
            binary_hash=binary_hash,
            analysis_data=analysis_data,
            metadata={"functions_count": len(analysis_result.functions)},
            parent_version=project.current_version,
            description=description,
            tags=tags or [],
        )

        # Update project
        project.versions.append(version)
        project.current_version = version_id
        project.modified_at = datetime.now()

        # Save to database
        self._save_version_to_db(project_id, version, str(version_path))
        self._update_project_in_db(project)

        return version

    def load_version(self, project_id: str, version_id: str) -> GhidraAnalysisResult | None:
        """Load a specific version of the analysis."""
        # Check cache
        cache_key = f"{project_id}_{version_id}"
        if cache_key in self.cache["analysis_results"]:
            cached_result = self.cache["analysis_results"][cache_key]
            if isinstance(cached_result, GhidraAnalysisResult):
                return cached_result

        project_dir = self.projects_dir / project_id
        version_path = project_dir / f"version_{version_id}.dat"

        if not version_path.exists():
            return None

        with open(version_path, "rb") as f:
            compressed_data = f.read()

        analysis_result = self._decompress_analysis(compressed_data)

        # Cache the result
        self.cache["analysis_results"][cache_key] = analysis_result

        return analysis_result

    def diff_versions(self, project_id: str, version1_id: str, version2_id: str) -> dict[str, Any]:
        """Perform binary diffing between two versions."""
        analysis1 = self.load_version(project_id, version1_id)
        analysis2 = self.load_version(project_id, version2_id)

        if not analysis1 or not analysis2:
            raise ValueError("One or both versions not found")

        diff_result: dict[str, Any] = {
            "added_functions": [],
            "removed_functions": [],
            "modified_functions": [],
            "added_strings": [],
            "removed_strings": [],
            "imports_changes": {"added": [], "removed": []},
            "exports_changes": {"added": [], "removed": []},
            "statistics": {},
        }

        # Compare functions
        funcs1 = set(analysis1.functions.keys())
        funcs2 = set(analysis2.functions.keys())

        # Added functions
        for addr in funcs2 - funcs1:
            func = analysis2.functions[addr]
            diff_result["added_functions"].append({"address": hex(addr), "name": func.name, "size": func.size})

        # Removed functions
        for addr in funcs1 - funcs2:
            func = analysis1.functions[addr]
            diff_result["removed_functions"].append({"address": hex(addr), "name": func.name, "size": func.size})

        # Modified functions
        for addr in funcs1 & funcs2:
            func1 = analysis1.functions[addr]
            func2 = analysis2.functions[addr]

            if self._function_changed(func1, func2):
                diff_result["modified_functions"].append(
                    {
                        "address": hex(addr),
                        "name": func2.name,
                        "changes": self._analyze_function_changes(func1, func2),
                    },
                )

        # Compare strings
        strings1_set = set(analysis1.strings)
        strings2_set = set(analysis2.strings)

        added_strings: list[tuple[int, str]] = [s for s in analysis2.strings if s in (strings2_set - strings1_set)]
        removed_strings: list[tuple[int, str]] = [s for s in analysis1.strings if s in (strings1_set - strings2_set)]
        diff_result["added_strings"] = added_strings
        diff_result["removed_strings"] = removed_strings

        # Compare imports
        imports1_set = set(analysis1.imports)
        imports2_set = set(analysis2.imports)

        added_imports: list[tuple[str, str, int]] = [i for i in analysis2.imports if i in (imports2_set - imports1_set)]
        removed_imports: list[tuple[str, str, int]] = [i for i in analysis1.imports if i in (imports1_set - imports2_set)]
        diff_result["imports_changes"]["added"] = added_imports
        diff_result["imports_changes"]["removed"] = removed_imports

        # Compare exports
        exports1_set = set(analysis1.exports)
        exports2_set = set(analysis2.exports)

        added_exports: list[tuple[str, int]] = [e for e in analysis2.exports if e in (exports2_set - exports1_set)]
        removed_exports: list[tuple[str, int]] = [e for e in analysis1.exports if e in (exports1_set - exports2_set)]
        diff_result["exports_changes"]["added"] = added_exports
        diff_result["exports_changes"]["removed"] = removed_exports

        # Calculate statistics
        diff_result["statistics"] = {
            "total_changes": (
                len(diff_result["added_functions"]) + len(diff_result["removed_functions"]) + len(diff_result["modified_functions"])
            ),
            "similarity_ratio": self._calculate_similarity(analysis1, analysis2),
        }

        return diff_result

    def _function_changed(self, func1: GhidraFunction, func2: GhidraFunction) -> bool:
        """Check if a function has changed between versions."""
        # Check basic properties
        if func1.size != func2.size or func1.signature != func2.signature or func1.return_type != func2.return_type:
            return True

        # Check decompiled code
        if func1.decompiled_code != func2.decompiled_code:
            return True

        # Check parameters
        return func1.parameters != func2.parameters

    def _analyze_function_changes(self, func1: GhidraFunction, func2: GhidraFunction) -> dict[str, Any]:
        """Analyze specific changes in a function."""
        changes: dict[str, Any] = {}

        if func1.size != func2.size:
            changes["size"] = {"old": func1.size, "new": func2.size}

        if func1.signature != func2.signature:
            changes["signature"] = {"old": func1.signature, "new": func2.signature}

        if func1.parameters != func2.parameters:
            changes["parameters"] = {"old": func1.parameters, "new": func2.parameters}

        if func1.decompiled_code != func2.decompiled_code:
            # Generate unified diff
            diff = difflib.unified_diff(func1.decompiled_code.splitlines(), func2.decompiled_code.splitlines(), lineterm="")
            changes["code_diff"] = list(diff)

        return changes

    def _calculate_similarity(self, analysis1: GhidraAnalysisResult, analysis2: GhidraAnalysisResult) -> float:
        """Calculate overall similarity between two analysis results."""
        # Simple similarity based on function overlap
        funcs1 = set(analysis1.functions.keys())
        funcs2 = set(analysis2.functions.keys())

        if not funcs1 and not funcs2:
            return 1.0

        intersection = len(funcs1 & funcs2)
        union = len(funcs1 | funcs2)

        return intersection / union if union > 0 else 0.0

    def export_project(self, project_id: str, export_path: str, include_all_versions: bool = False) -> Path:
        """Export project to a portable archive."""
        project = self.load_project(project_id)
        if not project:
            raise ValueError(f"Project {project_id} not found")

        export_path_obj = Path(export_path)

        with zipfile.ZipFile(export_path_obj, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Export project metadata
            project_data = {
                "project_id": project.project_id,
                "name": project.name,
                "binary_path": project.binary_path,
                "created_at": project.created_at.isoformat(),
                "modified_at": project.modified_at.isoformat(),
                "current_version": project.current_version,
                "settings": project.settings,
            }
            zipf.writestr("project.json", json.dumps(project_data, indent=2))

            # Export versions
            versions_to_export = (
                project.versions if include_all_versions else [v for v in project.versions if v.version_id == project.current_version]
            )

            for version in versions_to_export:
                version_path = self.projects_dir / project_id / f"version_{version.version_id}.dat"
                if version_path.exists():
                    zipf.write(version_path, f"versions/{version.version_id}.dat")

                # Export version metadata
                version_data = {
                    "version_id": version.version_id,
                    "timestamp": version.timestamp.isoformat(),
                    "binary_hash": version.binary_hash,
                    "parent_version": version.parent_version,
                    "author": version.author,
                    "description": version.description,
                    "tags": version.tags,
                }
                zipf.writestr(f"versions/{version.version_id}.json", json.dumps(version_data, indent=2))

        return export_path_obj

    def import_project(self, archive_path: str) -> GhidraProject:
        """Import project from archive."""
        archive_path_obj = Path(archive_path)

        with zipfile.ZipFile(archive_path_obj, "r") as zipf:
            # Read project metadata
            project_data = json.loads(zipf.read("project.json"))

            # Check if project already exists
            project_id = project_data["project_id"]
            if self.load_project(project_id):
                # Generate new ID for imported project
                project_id = self._generate_project_id(project_data["name"] + "_imported", project_data["binary_path"])

            # Create project directory
            project_dir = self.projects_dir / project_id
            project_dir.mkdir(exist_ok=True)

            # Import versions
            versions = []
            for filename in zipf.namelist():
                if filename.startswith("versions/") and filename.endswith(".json"):
                    version_data = json.loads(zipf.read(filename))

                    # Extract version data file
                    data_filename = f"versions/{version_data['version_id']}.dat"
                    if data_filename in zipf.namelist():
                        version_path = project_dir / f"version_{version_data['version_id']}.dat"
                        with open(version_path, "wb") as f:
                            f.write(zipf.read(data_filename))

                    version = ProjectVersion(
                        version_id=version_data["version_id"],
                        timestamp=datetime.fromisoformat(version_data["timestamp"]),
                        binary_hash=version_data["binary_hash"],
                        analysis_data=b"",  # Loaded on demand
                        metadata={},
                        parent_version=version_data.get("parent_version"),
                        author=version_data.get("author", "imported"),
                        description=version_data.get("description", ""),
                        tags=version_data.get("tags", []),
                    )
                    versions.append(version)

            # Create project
            project = GhidraProject(
                project_id=project_id,
                name=project_data["name"],
                binary_path=project_data["binary_path"],
                created_at=datetime.fromisoformat(project_data["created_at"]),
                modified_at=datetime.fromisoformat(project_data["modified_at"]),
                versions=versions,
                current_version=project_data["current_version"],
                collaborators=[],
                settings=project_data.get("settings", {}),
            )

            # Save to database
            self._save_project_to_db(project)
            for version in versions:
                version_path = project_dir / f"version_{version.version_id}.dat"
                self._save_version_to_db(project_id, version, str(version_path))

            return project

    def add_collaborator(self, project_id: str, user_id: str, role: str = "viewer") -> None:
        """Add a collaborator to the project."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO collaborators (project_id, user_id, role, added_at)
            VALUES (?, ?, ?, ?)
        """,
            (project_id, user_id, role, datetime.now().isoformat()),
        )

        conn.commit()
        conn.close()

        # Update cache if loaded
        if project_id in self.cache["projects"]:
            self.cache["projects"][project_id].collaborators.append(user_id)

    def lock_project(self, project_id: str) -> None:
        """Lock a project to prevent modifications."""
        if project := self.load_project(project_id):
            project.is_locked = True
            self._update_project_in_db(project)

    def unlock_project(self, project_id: str) -> None:
        """Unlock a project to allow modifications."""
        if project := self.load_project(project_id):
            project.is_locked = False
            self._update_project_in_db(project)

    def _compress_analysis(self, analysis: GhidraAnalysisResult) -> bytes:
        """Compress analysis result for storage."""
        # Convert to serializable format
        data = {
            "binary_path": analysis.binary_path,
            "architecture": analysis.architecture,
            "compiler": analysis.compiler,
            "entry_point": analysis.entry_point,
            "image_base": analysis.image_base,
            "functions": {addr: asdict(func) for addr, func in analysis.functions.items()},
            "data_types": {name: asdict(dt) for name, dt in analysis.data_types.items()},
            "strings": analysis.strings,
            "imports": analysis.imports,
            "exports": analysis.exports,
            "sections": analysis.sections,
            "vtables": analysis.vtables,
            "exception_handlers": analysis.exception_handlers,
            "metadata": analysis.metadata,
        }

        # Serialize with msgpack for efficiency
        serialized = msgpack.packb(data, use_bin_type=True)

        compressed = lz4.frame.compress(serialized, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX)
        return cast(bytes, compressed)

    def _decompress_analysis(self, compressed_data: bytes) -> GhidraAnalysisResult:
        """Decompress analysis result from storage."""
        # Decompress
        decompressed = lz4.frame.decompress(compressed_data)

        # Deserialize
        unpacked_data = msgpack.unpackb(decompressed, raw=False)
        data = cast(dict[str, Any], unpacked_data)

        functions = {int(addr): GhidraFunction(**func_data) for addr, func_data in data["functions"].items()}
        data_types = {name: GhidraDataType(**dt_data) for name, dt_data in data["data_types"].items()}
        return GhidraAnalysisResult(
            binary_path=data["binary_path"],
            architecture=data["architecture"],
            compiler=data["compiler"],
            functions=functions,
            data_types=data_types,
            strings=data["strings"],
            imports=data["imports"],
            exports=data["exports"],
            sections=data["sections"],
            entry_point=data["entry_point"],
            image_base=data["image_base"],
            vtables=data["vtables"],
            exception_handlers=data["exception_handlers"],
            metadata=data.get("metadata", {}),
        )

    def _generate_project_id(self, name: str, binary_path: str) -> str:
        """Generate unique project ID."""
        unique_str = f"{name}_{binary_path}_{datetime.now().isoformat()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def _generate_version_id(self) -> str:
        """Generate unique version ID."""
        unique_str = f"{datetime.now().isoformat()}_{os.urandom(16).hex()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _save_project_to_db(self, project: GhidraProject) -> None:
        """Save project to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO projects
            (project_id, name, binary_path, binary_hash, created_at, modified_at,
             current_version, is_locked, settings, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                project.project_id,
                project.name,
                project.binary_path,
                self._compute_file_hash(project.binary_path),
                project.created_at.isoformat(),
                project.modified_at.isoformat(),
                project.current_version,
                1 if project.is_locked else 0,
                json.dumps(project.settings),
                json.dumps({}),
            ),
        )

        conn.commit()
        conn.close()

    def _save_version_to_db(self, project_id: str, version: ProjectVersion, data_path: str) -> None:
        """Save version to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO versions
            (version_id, project_id, timestamp, binary_hash, parent_version,
             author, description, tags, data_path, data_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                version.version_id,
                project_id,
                version.timestamp.isoformat(),
                version.binary_hash,
                version.parent_version,
                version.author,
                version.description,
                json.dumps(version.tags),
                data_path,
                len(version.analysis_data) if version.analysis_data else 0,
            ),
        )

        conn.commit()
        conn.close()

    def _update_project_in_db(self, project: GhidraProject) -> None:
        """Update project in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE projects
            SET modified_at = ?, current_version = ?, is_locked = ?, settings = ?
            WHERE project_id = ?
        """,
            (
                project.modified_at.isoformat(),
                project.current_version,
                1 if project.is_locked else 0,
                json.dumps(project.settings),
                project.project_id,
            ),
        )

        conn.commit()
        conn.close()
