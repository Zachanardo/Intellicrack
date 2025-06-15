"""
C2 Infrastructure Manager

Central manager for C2 infrastructure operations.
"""

from ..c2.c2_server import C2Server
from ..c2.encryption_manager import EncryptionManager
from ..c2.session_manager import SessionManager


class C2Manager:
    """Central manager for C2 infrastructure operations."""

    def __init__(self):
        self.server = None
        self.sessions = SessionManager()
        self.encryption = EncryptionManager()

    def start_server(self, config):
        """Start C2 server with given configuration."""
        try:
            self.server = C2Server(config)
            result = self.server.start()
            return {
                'success': True,
                'server_info': {
                    'protocol': config.get('protocol', 'tcp'),
                    'port': config.get('port', 4444),
                    'interface': config.get('interface', '0.0.0.0')
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def stop_server(self):
        """Stop the C2 server."""
        if self.server:
            self.server.stop()
            self.server = None
        return {'success': True}

    def get_server_status(self):
        """Get the current server status and active sessions."""
        active_sessions = self.sessions.get_active_sessions() if hasattr(self.sessions, 'get_active_sessions') else []
        return {
            'running': self.server is not None,
            'active_sessions': len(active_sessions),
            'total_connections': self.sessions.total_connections if hasattr(self.sessions, 'total_connections') else 0,
            'sessions': [{
                'id': session.get('id', 'unknown'),
                'remote_ip': session.get('remote_ip', 'unknown'),
                'platform': session.get('platform', 'unknown')
            } for session in active_sessions]
        }
