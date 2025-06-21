"""
Beacon Manager for C2 Infrastructure

Manages beacon intervals, session health monitoring,
and communication scheduling for C2 operations.
"""

import logging
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BeaconManager:
    """
    Advanced beacon management system for C2 infrastructure.

    Handles session health monitoring, beacon scheduling,
    and adaptive communication intervals.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.BeaconManager")

        # Session tracking
        self.sessions = {}
        self.beacon_data = defaultdict(list)
        self.session_health = {}

        # Configuration
        self.default_beacon_interval = 60  # seconds
        self.max_missed_beacons = 3
        self.health_check_interval = 30  # seconds

        # Statistics
        self.stats = {
            'total_beacons': 0,
            'missed_beacons': 0,
            'active_sessions': 0,
            'inactive_sessions': 0,
            'average_response_time': 0.0,
            'last_update': time.time()
        }

        # Adaptive intervals
        self.adaptive_intervals = {}
        self.performance_metrics = defaultdict(list)

    def register_session(self, session_id: str, initial_config: Dict[str, Any] = None):
        """Register a new session for beacon management."""
        try:
            config = initial_config or {}

            self.sessions[session_id] = {
                'session_id': session_id,
                'registered_at': time.time(),
                'last_beacon': None,
                'beacon_interval': config.get('beacon_interval', self.default_beacon_interval),
                'jitter_percent': config.get('jitter_percent', 20),
                'missed_beacons': 0,
                'total_beacons': 0,
                'status': 'active',
                'client_info': config.get('client_info', {}),
                'performance_score': 1.0
            }

            self.session_health[session_id] = {
                'last_seen': time.time(),
                'response_times': [],
                'connection_quality': 'good',
                'adaptive_interval': self.default_beacon_interval
            }

            self.adaptive_intervals[session_id] = self.default_beacon_interval

            self.logger.info(f"Registered session {session_id} for beacon management")

        except Exception as e:
            self.logger.error(f"Failed to register session {session_id}: {e}")

    def unregister_session(self, session_id: str):
        """Unregister a session from beacon management."""
        try:
            if session_id in self.sessions:
                del self.sessions[session_id]

            if session_id in self.session_health:
                del self.session_health[session_id]

            if session_id in self.adaptive_intervals:
                del self.adaptive_intervals[session_id]

            if session_id in self.beacon_data:
                del self.beacon_data[session_id]

            if session_id in self.performance_metrics:
                del self.performance_metrics[session_id]

            self.logger.info(f"Unregistered session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to unregister session {session_id}: {e}")

    def update_beacon(self, session_id: str, beacon_data: Dict[str, Any]):
        """Update beacon information for a session."""
        try:
            current_time = time.time()

            if session_id not in self.sessions:
                self.logger.warning(f"Received beacon from unknown session: {session_id}")
                return

            session = self.sessions[session_id]
            health = self.session_health[session_id]

            # Calculate response time if previous beacon exists
            if session['last_beacon']:
                response_time = current_time - session['last_beacon']
                health['response_times'].append(response_time)

                # Keep only last 10 response times
                if len(health['response_times']) > 10:
                    health['response_times'] = health['response_times'][-10:]

            # Update session data
            session['last_beacon'] = current_time
            session['total_beacons'] += 1
            session['missed_beacons'] = 0  # Reset missed beacon counter
            session['status'] = 'active'

            # Update health data
            health['last_seen'] = current_time

            # Store beacon data for analysis
            self.beacon_data[session_id].append({
                'timestamp': current_time,
                'data': beacon_data,
                'response_time': health['response_times'][-1] if health['response_times'] else 0
            })

            # Keep only last 50 beacon records per session
            if len(self.beacon_data[session_id]) > 50:
                self.beacon_data[session_id] = self.beacon_data[session_id][-50:]

            # Update performance metrics
            self._update_performance_metrics(session_id, beacon_data)

            # Update adaptive interval
            self._update_adaptive_interval(session_id)

            # Update global statistics
            self.stats['total_beacons'] += 1

            self.logger.debug(f"Updated beacon for session {session_id}")

        except Exception as e:
            self.logger.error(f"Failed to update beacon for session {session_id}: {e}")

    def check_inactive_sessions(self) -> List[str]:
        """Check for inactive sessions and return list of session IDs."""
        inactive_sessions = []
        current_time = time.time()

        try:
            for session_id, session in self.sessions.items():
                if session['status'] == 'inactive':
                    continue

                # Calculate expected next beacon time
                last_beacon = session['last_beacon'] or session['registered_at']
                expected_interval = self.adaptive_intervals.get(session_id, session['beacon_interval'])
                time_since_last = current_time - last_beacon

                # Account for jitter (add 50% tolerance)
                tolerance = expected_interval * 1.5

                if time_since_last > tolerance:
                    session['missed_beacons'] += 1

                    if session['missed_beacons'] >= self.max_missed_beacons:
                        session['status'] = 'inactive'
                        inactive_sessions.append(session_id)
                        self.logger.warning(f"Session {session_id} marked as inactive after {session['missed_beacons']} missed beacons")

            return inactive_sessions

        except Exception as e:
            self.logger.error(f"Error checking inactive sessions: {e}")
            return []

    def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for a specific session."""
        try:
            if session_id not in self.sessions:
                return None

            session = self.sessions[session_id]
            health = self.session_health[session_id]

            # Calculate average response time
            avg_response_time = 0.0
            if health['response_times']:
                avg_response_time = sum(health['response_times']) / len(health['response_times'])

            # Calculate uptime
            uptime = time.time() - session['registered_at']

            return {
                'session_id': session_id,
                'status': session['status'],
                'last_beacon': session['last_beacon'],
                'total_beacons': session['total_beacons'],
                'missed_beacons': session['missed_beacons'],
                'beacon_interval': session['beacon_interval'],
                'adaptive_interval': self.adaptive_intervals.get(session_id),
                'uptime_seconds': uptime,
                'average_response_time': avg_response_time,
                'connection_quality': health['connection_quality'],
                'performance_score': session['performance_score'],
                'last_seen': health['last_seen']
            }

        except Exception as e:
            self.logger.error(f"Error getting session status for {session_id}: {e}")
            return None

    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs."""
        try:
            return [
                session_id for session_id, session in self.sessions.items()
                if session['status'] == 'active'
            ]
        except Exception as e:
            self.logger.error(f"Error getting active sessions: {e}")
            return []

    def update_beacon_interval(self, session_id: str, new_interval: int):
        """Update beacon interval for a specific session."""
        try:
            if session_id in self.sessions:
                self.sessions[session_id]['beacon_interval'] = new_interval
                self.adaptive_intervals[session_id] = new_interval
                self.logger.info(f"Updated beacon interval for session {session_id} to {new_interval}s")
            else:
                self.logger.warning(f"Cannot update interval for unknown session: {session_id}")

        except Exception as e:
            self.logger.error(f"Error updating beacon interval for {session_id}: {e}")

    def get_recommended_interval(self, session_id: str) -> int:
        """Get recommended beacon interval based on performance analysis."""
        try:
            if session_id not in self.sessions:
                return self.default_beacon_interval

            health = self.session_health[session_id]
            session = self.sessions[session_id]

            # Base interval
            base_interval = session['beacon_interval']

            # Adjust based on connection quality
            if health['connection_quality'] == 'excellent':
                return max(base_interval // 2, 30)  # Minimum 30 seconds
            elif health['connection_quality'] == 'good':
                return base_interval
            elif health['connection_quality'] == 'poor':
                return min(base_interval * 2, 300)  # Maximum 5 minutes
            else:  # bad
                return min(base_interval * 3, 600)  # Maximum 10 minutes

        except Exception as e:
            self.logger.error(f"Error calculating recommended interval for {session_id}: {e}")
            return self.default_beacon_interval

    def update_statistics(self):
        """Update global beacon statistics."""
        try:
            current_time = time.time()

            # Count active/inactive sessions
            active_count = len([s for s in self.sessions.values() if s['status'] == 'active'])
            inactive_count = len([s for s in self.sessions.values() if s['status'] == 'inactive'])

            # Calculate average response time across all sessions
            all_response_times = []
            for health in self.session_health.values():
                all_response_times.extend(health['response_times'])

            avg_response_time = 0.0
            if all_response_times:
                avg_response_time = sum(all_response_times) / len(all_response_times)

            # Update statistics
            self.stats.update({
                'active_sessions': active_count,
                'inactive_sessions': inactive_count,
                'average_response_time': avg_response_time,
                'last_update': current_time
            })

        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get beacon management statistics."""
        try:
            self.update_statistics()
            return self.stats.copy()
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}

    def _update_performance_metrics(self, session_id: str, beacon_data: Dict[str, Any]):
        """Update performance metrics for a session."""
        try:
            metrics = self.performance_metrics[session_id]
            current_time = time.time()

            # Extract performance data from beacon
            cpu_usage = beacon_data.get('system_status', {}).get('cpu_percent', 0)
            memory_usage = beacon_data.get('system_status', {}).get('memory_percent', 0)

            # Store performance metric
            metrics.append({
                'timestamp': current_time,
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'beacon_size': len(str(beacon_data))
            })

            # Keep only last 20 metrics
            if len(metrics) > 20:
                self.performance_metrics[session_id] = metrics[-20:]

        except Exception as e:
            self.logger.error(f"Error updating performance metrics for {session_id}: {e}")

    def _update_adaptive_interval(self, session_id: str):
        """Update adaptive beacon interval based on performance and connection quality."""
        try:
            if session_id not in self.session_health:
                return

            health = self.session_health[session_id]
            session = self.sessions[session_id]

            # Analyze recent response times
            response_times = health['response_times']
            if len(response_times) < 3:
                return  # Need more data

            avg_response_time = sum(response_times) / len(response_times)
            response_variance = sum((t - avg_response_time) ** 2 for t in response_times) / len(response_times)

            # Determine connection quality
            if avg_response_time < 1.0 and response_variance < 0.5:
                connection_quality = 'excellent'
            elif avg_response_time < 2.0 and response_variance < 1.0:
                connection_quality = 'good'
            elif avg_response_time < 5.0 and response_variance < 3.0:
                connection_quality = 'poor'
            else:
                connection_quality = 'bad'

            health['connection_quality'] = connection_quality

            # Calculate performance score
            performance_score = max(0.1, min(1.0, 1.0 / (1.0 + avg_response_time)))
            session['performance_score'] = performance_score

            # Update adaptive interval
            recommended_interval = self.get_recommended_interval(session_id)
            self.adaptive_intervals[session_id] = recommended_interval

        except Exception as e:
            self.logger.error(f"Error updating adaptive interval for {session_id}: {e}")

    def get_beacon_history(self, session_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get beacon history for a session."""
        try:
            if session_id not in self.beacon_data:
                return []

            history = self.beacon_data[session_id]
            return history[-limit:] if limit else history

        except Exception as e:
            self.logger.error(f"Error getting beacon history for {session_id}: {e}")
            return []

    def cleanup_old_data(self, max_age_hours: int = 24):
        """Cleanup old beacon data and performance metrics."""
        try:
            cutoff_time = time.time() - (max_age_hours * 3600)

            # Clean beacon data
            for session_id in list(self.beacon_data.keys()):
                self.beacon_data[session_id] = [
                    beacon for beacon in self.beacon_data[session_id]
                    if beacon['timestamp'] > cutoff_time
                ]

                # Remove empty entries
                if not self.beacon_data[session_id]:
                    del self.beacon_data[session_id]

            # Clean performance metrics
            for session_id in list(self.performance_metrics.keys()):
                self.performance_metrics[session_id] = [
                    metric for metric in self.performance_metrics[session_id]
                    if metric['timestamp'] > cutoff_time
                ]

                # Remove empty entries
                if not self.performance_metrics[session_id]:
                    del self.performance_metrics[session_id]

            self.logger.info(f"Cleaned up beacon data older than {max_age_hours} hours")

        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
