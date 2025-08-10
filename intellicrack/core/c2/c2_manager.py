"""C2 Infrastructure Manager

Central manager for C2 infrastructure operations.

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

from typing import Any

from ...utils.logger import get_logger
from .c2_server import C2Server


class C2Manager:
    """Central manager for C2 infrastructure operations."""

    def __init__(self):
        """Initialize the C2 manager with protocol and session management."""
        self.protocols = {}
        self.sessions = {}
        self.logger = get_logger(__name__)

    def start_server(self, config):
        """Start C2 server with given configuration."""
        try:
            self.server = C2Server(config)
            result = self.server.start()

            # Check if server started successfully
            if not result or not result.get("success", True):
                raise Exception(
                    f"Server failed to start: {result.get('error', 'Unknown error') if result else 'No response'}"
                )

            return {
                "success": True,
                "server_info": {
                    "protocol": config.get("protocol", "tcp"),
                    "port": config.get("port", 4444),
                    "interface": config.get("interface", "0.0.0.0"),
                    "startup_result": result,
                },
            }
        except Exception as e:
            self.logger.error("Exception in c2_manager: %s", e)
            return {
                "success": False,
                "error": str(e),
            }

    def stop_server(self):
        """Stop the C2 server."""
        if self.server:
            self.server.stop()
            self.server = None
        return {"success": True}

    def get_server_status(self):
        """Get the current server status and active sessions."""
        active_sessions = (
            self.sessions.get_active_sessions()
            if hasattr(self.sessions, "get_active_sessions")
            else []
        )
        return {
            "running": self.server is not None,
            "active_sessions": len(active_sessions),
            "total_connections": self.sessions.total_connections
            if hasattr(self.sessions, "total_connections")
            else 0,
            "sessions": [
                {
                    "id": session.get("id", "unknown"),
                    "remote_ip": session.get("remote_ip", "unknown"),
                    "platform": session.get("platform", "unknown"),
                }
                for session in active_sessions
            ],
        }

    def wait_for_callback(self, session_id: str = None, timeout: int = 300) -> dict[str, Any]:
        """Wait for a callback from an agent."""
        try:
            import time

            start_time = time.time()

            self.logger.info(
                f"Waiting for callback from session {session_id or 'any'} with timeout {timeout}s"
            )

            while time.time() - start_time < timeout:
                # Check for active sessions
                active_sessions = (
                    self.sessions.get_active_sessions()
                    if hasattr(self.sessions, "get_active_sessions")
                    else []
                )

                if session_id:
                    # Wait for specific session
                    for session in active_sessions:
                        if session.get("id") == session_id:
                            return {
                                "success": True,
                                "session_id": session_id,
                                "session_info": session,
                                "wait_time": time.time() - start_time,
                            }
                # Wait for any callback
                elif active_sessions:
                    return {
                        "success": True,
                        "session_id": active_sessions[0].get("id"),
                        "session_info": active_sessions[0],
                        "wait_time": time.time() - start_time,
                    }

                time.sleep(1)  # Check every second

            return {
                "success": False,
                "error": f"No callback received within {timeout} seconds",
                "wait_time": timeout,
            }

        except Exception as e:
            self.logger.error("Exception in c2_manager: %s", e)
            return {"success": False, "error": str(e)}

    def establish_session(
        self, target_info: dict[str, Any], payload_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Establish a C2 session with a target."""
        try:
            import time
            import uuid

            session_id = str(uuid.uuid4())

            self.logger.info(
                f"Establishing C2 session {session_id} with target {target_info.get('target_ip', 'unknown')}"
            )

            # Create session info
            session_info = {
                "id": session_id,
                "target_ip": target_info.get("target_ip", "unknown"),
                "target_port": target_info.get("target_port", 0),
                "platform": target_info.get("platform", "unknown"),
                "payload_type": payload_info.get("type", "unknown"),
                "established_at": time.time(),
                "status": "establishing",
            }

            # Try to establish connection
            if self.server:
                # Add session to active sessions
                if hasattr(self.sessions, "add_session"):
                    self.sessions.add_session(session_info)

                # Wait for initial callback
                callback_result = self.wait_for_callback(session_id, timeout=60)

                if callback_result["success"]:
                    session_info["status"] = "established"
                    return {
                        "success": True,
                        "session_id": session_id,
                        "session_info": session_info,
                        "callback_time": callback_result.get("wait_time", 0),
                    }
                session_info["status"] = "failed"
                return {
                    "success": False,
                    "error": "Failed to receive initial callback",
                    "session_id": session_id,
                }
            return {"success": False, "error": "C2 server not running"}

        except Exception as e:
            self.logger.error("Exception in c2_manager: %s", e)
            return {"success": False, "error": str(e)}
