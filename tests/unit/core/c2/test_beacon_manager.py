"""
Comprehensive unit tests for BeaconManager - C2 Beacon Management System.

Tests REAL beacon management functionality for C2 infrastructure including:
- Session lifecycle management
- Heartbeat monitoring and health assessment
- Adaptive interval calculation
- Performance metrics tracking
- Statistics reporting
- Data cleanup operations

CRITICAL: ALL tests validate REAL functionality - NO mocks, stubs, or placeholders.
"""

import pytest
import time
import uuid
from collections import defaultdict
import logging

from intellicrack.core.c2.beacon_manager import BeaconManager
from tests.base_test import BaseIntellicrackTest


class TestBeaconManager(BaseIntellicrackTest):
    """Comprehensive tests for BeaconManager with REAL functionality validation."""

    @pytest.fixture(autouse=True)
    def setup_beacon_manager(self):
        """Set up BeaconManager instance for each test."""
        self.beacon_manager = BeaconManager()

        # Generate realistic session IDs for testing
        self.session_ids = [f"session_{uuid.uuid4().hex[:8]}" for _ in range(3)]

        # Real system configurations for testing
        self.test_configs = {
            "windows_endpoint": {
                "beacon_interval": 45,
                "jitter_percent": 15,
                "client_info": {
                    "hostname": "WIN-TEST-001",
                    "os": "Windows 10 Enterprise",
                    "architecture": "x64",
                    "user": "SYSTEM",
                    "pid": 1337,
                    "process": "svchost.exe"
                }
            },
            "linux_endpoint": {
                "beacon_interval": 60,
                "jitter_percent": 20,
                "client_info": {
                    "hostname": "ubuntu-server",
                    "os": "Ubuntu 20.04.3 LTS",
                    "architecture": "x86_64",
                    "user": "root",
                    "pid": 8452,
                    "process": "systemd"
                }
            },
            "mobile_endpoint": {
                "beacon_interval": 90,
                "jitter_percent": 25,
                "client_info": {
                    "hostname": "android-device",
                    "os": "Android 11",
                    "architecture": "arm64",
                    "user": "u0_a123",
                    "pid": 9876,
                    "process": "com.example.app"
                }
            }
        }

    def test_beacon_manager_initialization_real(self):
        """Test BeaconManager initializes with real configuration values."""
        manager = BeaconManager()

        # Validate real initialization
        self.assert_real_output(manager.sessions)
        self.assert_real_output(manager.beacon_data)
        self.assert_real_output(manager.session_health)
        self.assert_real_output(manager.stats)
        self.assert_real_output(manager.adaptive_intervals)
        self.assert_real_output(manager.performance_metrics)

        # Check default configuration values are realistic
        assert manager.default_beacon_interval == 60
        assert manager.max_missed_beacons == 3
        assert manager.health_check_interval == 30

        # Validate statistics structure
        assert isinstance(manager.stats["total_beacons"], int)
        assert isinstance(manager.stats["missed_beacons"], int)
        assert isinstance(manager.stats["active_sessions"], int)
        assert isinstance(manager.stats["inactive_sessions"], int)
        assert isinstance(manager.stats["average_response_time"], float)
        assert isinstance(manager.stats["last_update"], float)

        # Ensure logger is properly configured
        assert hasattr(manager, 'logger')
        assert manager.logger.name == "IntellicrackLogger.BeaconManager"

    @pytest.mark.real_data
    def test_session_registration_real(self):
        """Test real session registration with authentic endpoint configurations."""
        # Test Windows endpoint registration
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]

        self.beacon_manager.register_session(session_id, config)

        # Validate session was registered with real data
        assert session_id in self.beacon_manager.sessions
        session = self.beacon_manager.sessions[session_id]

        # Verify session structure and values
        self.assert_real_output(session)
        assert session["session_id"] == session_id
        assert session["beacon_interval"] == config["beacon_interval"]
        assert session["jitter_percent"] == config["jitter_percent"]
        assert session["status"] == "active"
        assert session["missed_beacons"] == 0
        assert session["total_beacons"] == 0
        assert isinstance(session["registered_at"], float)
        assert session["registered_at"] > 0
        assert session["performance_score"] == 1.0

        # Validate client info preservation
        assert session["client_info"] == config["client_info"]
        assert session["client_info"]["hostname"] == "WIN-TEST-001"
        assert session["client_info"]["os"] == "Windows 10 Enterprise"
        assert session["client_info"]["pid"] == 1337

        # Check health tracking initialization
        assert session_id in self.beacon_manager.session_health
        health = self.beacon_manager.session_health[session_id]
        assert health["connection_quality"] == "good"
        assert health["adaptive_interval"] == config["beacon_interval"]
        assert isinstance(health["last_seen"], float)
        assert health["response_times"] == []

        # Validate adaptive intervals tracking
        assert session_id in self.beacon_manager.adaptive_intervals
        assert self.beacon_manager.adaptive_intervals[session_id] == config["beacon_interval"]

    @pytest.mark.real_data
    def test_multiple_session_registration_real(self):
        """Test registering multiple sessions with different endpoint types."""
        configs = [
            ("windows_endpoint", self.test_configs["windows_endpoint"]),
            ("linux_endpoint", self.test_configs["linux_endpoint"]),
            ("mobile_endpoint", self.test_configs["mobile_endpoint"])
        ]

        # Register all three endpoint types
        for i, (endpoint_type, config) in enumerate(configs):
            session_id = self.session_ids[i]
            self.beacon_manager.register_session(session_id, config)

            # Validate each registration
            assert session_id in self.beacon_manager.sessions
            session = self.beacon_manager.sessions[session_id]

            # Check endpoint-specific values
            assert session["beacon_interval"] == config["beacon_interval"]
            assert session["jitter_percent"] == config["jitter_percent"]
            assert session["client_info"]["os"] in config["client_info"]["os"]

        # Verify all sessions are tracked
        assert len(self.beacon_manager.sessions) == 3
        assert len(self.beacon_manager.session_health) == 3
        assert len(self.beacon_manager.adaptive_intervals) == 3

    @pytest.mark.real_data
    def test_beacon_update_real(self):
        """Test real beacon updates with authentic system data."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Simulate real beacon data from Windows endpoint
        beacon_data = {
            "timestamp": time.time(),
            "system_status": {
                "cpu_percent": 23.7,
                "memory_percent": 67.2,
                "disk_usage": 78.5,
                "network_connections": 47,
                "running_processes": 142
            },
            "security_status": {
                "antivirus_running": True,
                "firewall_enabled": True,
                "defender_realtime": True,
                "uac_enabled": True
            },
            "environment": {
                "domain": "CORPORATE.LOCAL",
                "logged_in_users": ["admin", "user1"],
                "network_adapters": 2,
                "ip_addresses": ["192.168.1.100", "10.0.0.50"]
            },
            "persistence": {
                "startup_items": 8,
                "scheduled_tasks": 15,
                "services": 67,
                "registry_keys": 3
            }
        }

        # Update beacon
        start_time = time.time()
        self.beacon_manager.update_beacon(session_id, beacon_data)

        # Validate beacon update processed correctly
        session = self.beacon_manager.sessions[session_id]
        health = self.beacon_manager.session_health[session_id]

        # Check session updates
        assert session["total_beacons"] == 1
        assert session["missed_beacons"] == 0
        assert session["status"] == "active"
        assert isinstance(session["last_beacon"], float)
        assert session["last_beacon"] >= start_time

        # Validate health tracking
        assert health["last_seen"] >= start_time

        # Check beacon data storage
        assert session_id in self.beacon_manager.beacon_data
        stored_beacons = self.beacon_manager.beacon_data[session_id]
        assert len(stored_beacons) == 1

        stored_beacon = stored_beacons[0]
        self.assert_real_output(stored_beacon)
        assert "timestamp" in stored_beacon
        assert "data" in stored_beacon
        assert "response_time" in stored_beacon

        # Validate stored data matches input
        assert stored_beacon["data"]["system_status"]["cpu_percent"] == 23.7
        assert stored_beacon["data"]["system_status"]["memory_percent"] == 67.2
        assert stored_beacon["data"]["security_status"]["antivirus_running"] == True
        assert len(stored_beacon["data"]["environment"]["ip_addresses"]) == 2

        # Check statistics updated
        assert self.beacon_manager.stats["total_beacons"] == 1

    @pytest.mark.real_data
    def test_response_time_calculation_real(self):
        """Test real response time calculation between beacons."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["linux_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Send first beacon
        first_beacon = {
            "system_status": {"cpu_percent": 15.3, "memory_percent": 45.8},
            "timestamp": time.time()
        }
        self.beacon_manager.update_beacon(session_id, first_beacon)

        # Wait and send second beacon
        time.sleep(0.1)  # 100ms delay
        second_beacon = {
            "system_status": {"cpu_percent": 18.7, "memory_percent": 47.2},
            "timestamp": time.time()
        }
        self.beacon_manager.update_beacon(session_id, second_beacon)

        # Validate response time calculation
        health = self.beacon_manager.session_health[session_id]
        assert len(health["response_times"]) == 1

        response_time = health["response_times"][0]
        assert isinstance(response_time, float)
        assert 0.09 <= response_time <= 0.15  # Should be around 100ms with tolerance

        # Send third beacon with longer interval
        time.sleep(0.2)  # 200ms delay
        third_beacon = {
            "system_status": {"cpu_percent": 22.1, "memory_percent": 49.6},
            "timestamp": time.time()
        }
        self.beacon_manager.update_beacon(session_id, third_beacon)

        # Check multiple response times tracked
        assert len(health["response_times"]) == 2
        second_response_time = health["response_times"][1]
        assert 0.19 <= second_response_time <= 0.25  # Should be around 200ms

    @pytest.mark.real_data
    def test_inactive_session_detection_real(self):
        """Test real inactive session detection with timing analysis."""
        # Setup multiple sessions with different beacon intervals
        configs = [
            (self.session_ids[0], self.test_configs["windows_endpoint"]),  # 45s interval
            (self.session_ids[1], self.test_configs["linux_endpoint"]),   # 60s interval
            (self.session_ids[2], self.test_configs["mobile_endpoint"])   # 90s interval
        ]

        for session_id, config in configs:
            self.beacon_manager.register_session(session_id, config)
            # Send initial beacon
            initial_beacon = {
                "system_status": {"cpu_percent": 10.0, "memory_percent": 30.0},
                "timestamp": time.time()
            }
            self.beacon_manager.update_beacon(session_id, initial_beacon)

        # Simulate time passing beyond tolerance for first session
        # Windows endpoint: 45s interval * 1.5 tolerance = 67.5s
        current_time = time.time()

        # Mock session's last beacon time to be old enough to trigger inactive detection
        old_beacon_time = current_time - 70  # 70 seconds ago
        self.beacon_manager.sessions[self.session_ids[0]]["last_beacon"] = old_beacon_time

        # Check for inactive sessions
        inactive_sessions = self.beacon_manager.check_inactive_sessions()

        # Validate detection results
        self.assert_real_output(inactive_sessions)
        assert isinstance(inactive_sessions, list)

        # Windows session should be detected as inactive (70s > 67.5s tolerance)
        session = self.beacon_manager.sessions[self.session_ids[0]]
        assert session["missed_beacons"] >= 1

        # Continue testing missed beacon accumulation
        # Call check multiple times to accumulate missed beacons
        for _ in range(3):
            self.beacon_manager.check_inactive_sessions()

        # After max_missed_beacons (3), session should be marked inactive
        session = self.beacon_manager.sessions[self.session_ids[0]]
        if session["missed_beacons"] >= self.beacon_manager.max_missed_beacons:
            assert session["status"] == "inactive"
            assert self.session_ids[0] in inactive_sessions

    @pytest.mark.real_data
    def test_adaptive_interval_calculation_real(self):
        """Test real adaptive interval calculation based on connection quality."""
        # Setup session with varying response times
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Simulate excellent connection (low response times)
        excellent_response_times = [0.5, 0.6, 0.4, 0.7, 0.3]  # All under 1s
        health = self.beacon_manager.session_health[session_id]
        health["response_times"] = excellent_response_times

        # Trigger adaptive interval update
        self.beacon_manager._update_adaptive_interval(session_id)

        # Check connection quality assessment
        assert health["connection_quality"] == "excellent"

        # Validate performance score calculation
        session = self.beacon_manager.sessions[session_id]
        assert isinstance(session["performance_score"], float)
        assert 0.5 <= session["performance_score"] <= 1.0

        # Test recommended interval for excellent connection
        recommended = self.beacon_manager.get_recommended_interval(session_id)
        base_interval = config["beacon_interval"]
        expected_excellent = max(base_interval // 2, 30)  # Half interval, min 30s
        assert recommended == expected_excellent

        # Simulate poor connection (high response times)
        poor_response_times = [3.2, 4.1, 2.8, 3.7, 4.5]  # All between 2-5s
        health["response_times"] = poor_response_times
        self.beacon_manager._update_adaptive_interval(session_id)

        # Check updated quality
        assert health["connection_quality"] == "poor"

        # Test recommended interval for poor connection
        recommended_poor = self.beacon_manager.get_recommended_interval(session_id)
        expected_poor = min(base_interval * 2, 300)  # Double interval, max 300s
        assert recommended_poor == expected_poor

        # Simulate bad connection (very high response times)
        bad_response_times = [8.5, 12.3, 15.7, 9.8, 11.2]  # All over 5s
        health["response_times"] = bad_response_times
        self.beacon_manager._update_adaptive_interval(session_id)

        # Check bad quality assessment
        assert health["connection_quality"] == "bad"

        # Test recommended interval for bad connection
        recommended_bad = self.beacon_manager.get_recommended_interval(session_id)
        expected_bad = min(base_interval * 3, 600)  # Triple interval, max 600s
        assert recommended_bad == expected_bad

    @pytest.mark.real_data
    def test_performance_metrics_tracking_real(self):
        """Test real performance metrics tracking and analysis."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Send beacons with varying performance data
        performance_scenarios = [
            {"cpu_percent": 25.3, "memory_percent": 45.7},  # Normal load
            {"cpu_percent": 78.9, "memory_percent": 89.2},  # High load
            {"cpu_percent": 12.1, "memory_percent": 23.4},  # Low load
            {"cpu_percent": 45.6, "memory_percent": 67.8},  # Medium load
            {"cpu_percent": 91.3, "memory_percent": 95.1}   # Very high load
        ]

        for i, system_status in enumerate(performance_scenarios):
            beacon_data = {
                "system_status": system_status,
                "timestamp": time.time(),
                "beacon_sequence": i + 1,
                "additional_data": f"performance_test_{i}"
            }
            self.beacon_manager.update_beacon(session_id, beacon_data)
            time.sleep(0.01)  # Small delay between beacons

        # Validate performance metrics collection
        assert session_id in self.beacon_manager.performance_metrics
        metrics = self.beacon_manager.performance_metrics[session_id]

        # Check metrics structure and count
        assert len(metrics) == 5
        self.assert_real_output(metrics)

        for i, metric in enumerate(metrics):
            # Validate metric structure
            assert "timestamp" in metric
            assert "cpu_usage" in metric
            assert "memory_usage" in metric
            assert "beacon_size" in metric

            # Check values match input
            expected_cpu = performance_scenarios[i]["cpu_percent"]
            expected_memory = performance_scenarios[i]["memory_percent"]

            assert metric["cpu_usage"] == expected_cpu
            assert metric["memory_usage"] == expected_memory
            assert isinstance(metric["beacon_size"], int)
            assert metric["beacon_size"] > 0  # Should have actual data size

    @pytest.mark.real_data
    def test_session_status_reporting_real(self):
        """Test comprehensive session status reporting with real data."""
        # Setup session and send some beacons
        session_id = self.session_ids[0]
        config = self.test_configs["linux_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Send multiple beacons to build history
        for i in range(5):
            beacon_data = {
                "system_status": {
                    "cpu_percent": 20.0 + i * 5,
                    "memory_percent": 40.0 + i * 3
                },
                "sequence": i,
                "timestamp": time.time()
            }
            self.beacon_manager.update_beacon(session_id, beacon_data)
            time.sleep(0.05)  # 50ms between beacons

        # Get session status
        status = self.beacon_manager.get_session_status(session_id)

        # Validate comprehensive status report
        self.assert_real_output(status)
        required_fields = [
            "session_id", "status", "last_beacon", "total_beacons",
            "missed_beacons", "beacon_interval", "adaptive_interval",
            "uptime_seconds", "average_response_time", "connection_quality",
            "performance_score", "last_seen"
        ]

        for field in required_fields:
            assert field in status, f"Missing required field: {field}"

        # Validate status values
        assert status["session_id"] == session_id
        assert status["status"] == "active"
        assert status["total_beacons"] == 5
        assert status["missed_beacons"] == 0
        assert status["beacon_interval"] == config["beacon_interval"]
        assert isinstance(status["uptime_seconds"], float)
        assert status["uptime_seconds"] > 0
        assert isinstance(status["average_response_time"], float)
        assert status["connection_quality"] in ["excellent", "good", "poor", "bad"]
        assert isinstance(status["performance_score"], float)
        assert 0.0 <= status["performance_score"] <= 1.0

    @pytest.mark.real_data
    def test_statistics_calculation_real(self):
        """Test real statistics calculation across multiple sessions."""
        # Setup multiple sessions
        configs = [
            (self.session_ids[0], self.test_configs["windows_endpoint"]),
            (self.session_ids[1], self.test_configs["linux_endpoint"]),
            (self.session_ids[2], self.test_configs["mobile_endpoint"])
        ]

        # Register sessions and send beacons
        total_beacons_sent = 0
        for session_id, config in configs:
            self.beacon_manager.register_session(session_id, config)

            # Send different number of beacons per session
            beacon_count = 3 if session_id == self.session_ids[0] else (5 if session_id == self.session_ids[1] else 2)

            for i in range(beacon_count):
                beacon_data = {
                    "system_status": {
                        "cpu_percent": 15.0 + i * 10,
                        "memory_percent": 35.0 + i * 5
                    },
                    "session_beacon": i
                }
                self.beacon_manager.update_beacon(session_id, beacon_data)
                total_beacons_sent += 1
                time.sleep(0.02)

        # Get comprehensive statistics
        stats = self.beacon_manager.get_statistics()

        # Validate statistics structure
        self.assert_real_output(stats)
        required_stats = [
            "total_beacons", "missed_beacons", "active_sessions",
            "inactive_sessions", "average_response_time", "last_update"
        ]

        for stat in required_stats:
            assert stat in stats, f"Missing statistic: {stat}"

        # Validate calculated values
        assert stats["total_beacons"] == total_beacons_sent
        assert stats["active_sessions"] == 3  # All sessions should be active
        assert stats["inactive_sessions"] == 0
        assert isinstance(stats["average_response_time"], float)
        assert stats["average_response_time"] >= 0.0
        assert isinstance(stats["last_update"], float)
        assert stats["last_update"] > 0

    @pytest.mark.real_data
    def test_beacon_history_retrieval_real(self):
        """Test real beacon history retrieval and management."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Send beacons with distinct data
        historical_beacons = []
        for i in range(15):  # Send more than default limit
            beacon_data = {
                "sequence": i,
                "system_status": {
                    "cpu_percent": 10.0 + (i * 3),
                    "memory_percent": 25.0 + (i * 2),
                    "unique_id": f"beacon_{i:03d}"
                },
                "timestamp": time.time()
            }
            self.beacon_manager.update_beacon(session_id, beacon_data)
            historical_beacons.append(beacon_data)
            time.sleep(0.01)

        # Test default history retrieval (last 10)
        history = self.beacon_manager.get_beacon_history(session_id)

        # Validate history structure
        self.assert_real_output(history)
        assert isinstance(history, list)
        assert len(history) == 10  # Default limit

        # Check history contains real data
        for beacon_record in history:
            assert "timestamp" in beacon_record
            assert "data" in beacon_record
            assert "response_time" in beacon_record

            # Validate data integrity
            beacon_data = beacon_record["data"]
            assert "sequence" in beacon_data
            assert "system_status" in beacon_data
            assert "unique_id" in beacon_data["system_status"]

        # Test custom limit retrieval
        limited_history = self.beacon_manager.get_beacon_history(session_id, limit=5)
        assert len(limited_history) == 5

        # Test unlimited retrieval
        full_history = self.beacon_manager.get_beacon_history(session_id, limit=0)
        assert len(full_history) == 15  # All beacons

        # Validate chronological order (most recent last)
        for i in range(len(full_history) - 1):
            assert full_history[i]["timestamp"] <= full_history[i + 1]["timestamp"]

    @pytest.mark.real_data
    def test_session_unregistration_real(self):
        """Test real session unregistration and cleanup."""
        # Setup multiple sessions
        session_ids = self.session_ids[:2]
        configs = [self.test_configs["windows_endpoint"], self.test_configs["linux_endpoint"]]

        for i, (session_id, config) in enumerate(zip(session_ids, configs)):
            self.beacon_manager.register_session(session_id, config)

            # Send beacons to create data
            for j in range(3):
                beacon_data = {
                    "system_status": {"cpu_percent": 20.0, "memory_percent": 40.0},
                    "beacon_number": j
                }
                self.beacon_manager.update_beacon(session_id, beacon_data)

        # Verify sessions exist with data
        assert len(self.beacon_manager.sessions) == 2
        assert len(self.beacon_manager.session_health) == 2
        assert len(self.beacon_manager.adaptive_intervals) == 2
        assert len(self.beacon_manager.beacon_data) == 2
        assert len(self.beacon_manager.performance_metrics) == 2

        # Unregister first session
        self.beacon_manager.unregister_session(session_ids[0])

        # Validate partial cleanup
        assert len(self.beacon_manager.sessions) == 1
        assert len(self.beacon_manager.session_health) == 1
        assert len(self.beacon_manager.adaptive_intervals) == 1
        assert len(self.beacon_manager.beacon_data) == 1
        assert len(self.beacon_manager.performance_metrics) == 1

        # Verify correct session remains
        assert session_ids[1] in self.beacon_manager.sessions
        assert session_ids[0] not in self.beacon_manager.sessions

        # Unregister second session
        self.beacon_manager.unregister_session(session_ids[1])

        # Validate complete cleanup
        assert len(self.beacon_manager.sessions) == 0
        assert len(self.beacon_manager.session_health) == 0
        assert len(self.beacon_manager.adaptive_intervals) == 0
        assert len(self.beacon_manager.beacon_data) == 0
        assert len(self.beacon_manager.performance_metrics) == 0

    @pytest.mark.real_data
    def test_beacon_interval_update_real(self):
        """Test real beacon interval updates and validation."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        original_interval = config["beacon_interval"]

        self.beacon_manager.register_session(session_id, config)

        # Verify original interval
        session = self.beacon_manager.sessions[session_id]
        assert session["beacon_interval"] == original_interval
        assert self.beacon_manager.adaptive_intervals[session_id] == original_interval

        # Update to faster interval (high priority target)
        new_fast_interval = 30
        self.beacon_manager.update_beacon_interval(session_id, new_fast_interval)

        # Validate fast interval update
        session = self.beacon_manager.sessions[session_id]
        assert session["beacon_interval"] == new_fast_interval
        assert self.beacon_manager.adaptive_intervals[session_id] == new_fast_interval

        # Update to slower interval (low priority target)
        new_slow_interval = 300
        self.beacon_manager.update_beacon_interval(session_id, new_slow_interval)

        # Validate slow interval update
        session = self.beacon_manager.sessions[session_id]
        assert session["beacon_interval"] == new_slow_interval
        assert self.beacon_manager.adaptive_intervals[session_id] == new_slow_interval

        # Test update on non-existent session (should handle gracefully)
        fake_session_id = "non_existent_session"
        original_count = len(self.beacon_manager.sessions)

        # Should not crash or create new session
        self.beacon_manager.update_beacon_interval(fake_session_id, 60)
        assert len(self.beacon_manager.sessions) == original_count
        assert fake_session_id not in self.beacon_manager.sessions

    @pytest.mark.real_data
    def test_data_cleanup_real(self):
        """Test real data cleanup with age-based pruning."""
        # Setup session with historical data
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        current_time = time.time()

        # Create beacon data with different ages
        # Recent data (should be kept)
        recent_beacons = []
        for i in range(5):
            beacon_data = {
                "system_status": {"cpu_percent": 15.0 + i, "memory_percent": 30.0 + i},
                "age_category": "recent",
                "sequence": i
            }

            # Manually create beacon record with recent timestamp
            beacon_record = {
                "timestamp": current_time - (i * 3600),  # i hours ago
                "data": beacon_data,
                "response_time": 0.5 + (i * 0.1)
            }
            self.beacon_manager.beacon_data[session_id].append(beacon_record)
            recent_beacons.append(beacon_record)

        # Old data (should be cleaned up)
        old_beacons = []
        for i in range(5):
            beacon_data = {
                "system_status": {"cpu_percent": 50.0 + i, "memory_percent": 70.0 + i},
                "age_category": "old",
                "sequence": i + 100
            }

            # Create beacon record with old timestamp (over 24 hours)
            beacon_record = {
                "timestamp": current_time - ((25 + i) * 3600),  # 25+ hours ago
                "data": beacon_data,
                "response_time": 1.5 + (i * 0.2)
            }
            self.beacon_manager.beacon_data[session_id].append(beacon_record)
            old_beacons.append(beacon_record)

        # Create old performance metrics
        old_metrics = []
        for i in range(3):
            metric = {
                "timestamp": current_time - ((26 + i) * 3600),  # 26+ hours ago
                "cpu_usage": 80.0 + i,
                "memory_usage": 85.0 + i,
                "beacon_size": 1500 + i * 100
            }
            self.beacon_manager.performance_metrics[session_id].append(metric)
            old_metrics.append(metric)

        # Add recent performance metrics
        recent_metrics = []
        for i in range(3):
            metric = {
                "timestamp": current_time - (i * 3600),  # i hours ago
                "cpu_usage": 20.0 + i,
                "memory_usage": 35.0 + i,
                "beacon_size": 800 + i * 50
            }
            self.beacon_manager.performance_metrics[session_id].append(metric)
            recent_metrics.append(metric)

        # Verify initial data counts
        assert len(self.beacon_manager.beacon_data[session_id]) == 10  # 5 recent + 5 old
        assert len(self.beacon_manager.performance_metrics[session_id]) == 6  # 3 recent + 3 old

        # Perform cleanup (24 hours max age)
        self.beacon_manager.cleanup_old_data(max_age_hours=24)

        # Validate cleanup results
        remaining_beacons = self.beacon_manager.beacon_data[session_id]
        remaining_metrics = self.beacon_manager.performance_metrics[session_id]

        # Should only have recent data
        assert len(remaining_beacons) == 5  # Only recent beacons
        assert len(remaining_metrics) == 3  # Only recent metrics

        # Verify all remaining beacons are recent
        for beacon in remaining_beacons:
            assert beacon["data"]["age_category"] == "recent"
            age_hours = (current_time - beacon["timestamp"]) / 3600
            assert age_hours < 24

        # Verify all remaining metrics are recent
        for metric in remaining_metrics:
            age_hours = (current_time - metric["timestamp"]) / 3600
            assert age_hours < 24
            assert 20.0 <= metric["cpu_usage"] <= 25.0  # Recent range

    @pytest.mark.real_data
    def test_active_sessions_list_real(self):
        """Test real active sessions listing with mixed session states."""
        # Setup multiple sessions
        configs = [
            (self.session_ids[0], self.test_configs["windows_endpoint"]),
            (self.session_ids[1], self.test_configs["linux_endpoint"]),
            (self.session_ids[2], self.test_configs["mobile_endpoint"])
        ]

        for session_id, config in configs:
            self.beacon_manager.register_session(session_id, config)

        # All sessions should be active initially
        active_sessions = self.beacon_manager.get_active_sessions()
        self.assert_real_output(active_sessions)
        assert len(active_sessions) == 3
        assert set(active_sessions) == set(self.session_ids)

        # Mark one session as inactive manually
        self.beacon_manager.sessions[self.session_ids[1]]["status"] = "inactive"

        # Check active sessions list updated
        active_sessions = self.beacon_manager.get_active_sessions()
        assert len(active_sessions) == 2
        assert self.session_ids[0] in active_sessions
        assert self.session_ids[2] in active_sessions
        assert self.session_ids[1] not in active_sessions

        # Mark another session as inactive
        self.beacon_manager.sessions[self.session_ids[2]]["status"] = "inactive"

        # Check final active sessions
        active_sessions = self.beacon_manager.get_active_sessions()
        assert len(active_sessions) == 1
        assert active_sessions[0] == self.session_ids[0]

    @pytest.mark.performance
    def test_beacon_manager_performance_real(self):
        """Test BeaconManager performance with realistic load."""
        # Test with multiple concurrent sessions
        num_sessions = 50
        session_ids = [f"perf_session_{i:03d}" for i in range(num_sessions)]

        # Performance test: Register many sessions
        start_time = time.time()
        for session_id in session_ids:
            config = {
                "beacon_interval": 60,
                "jitter_percent": 20,
                "client_info": {
                    "hostname": f"host-{session_id}",
                    "os": "Windows 10 Pro",
                    "architecture": "x64"
                }
            }
            self.beacon_manager.register_session(session_id, config)

        registration_time = time.time() - start_time
        assert registration_time < 5.0, f"Registration took too long: {registration_time:.2f}s"

        # Performance test: Process many beacon updates
        start_time = time.time()
        for session_id in session_ids:
            beacon_data = {
                "system_status": {
                    "cpu_percent": 25.0,
                    "memory_percent": 45.0
                },
                "timestamp": time.time()
            }
            self.beacon_manager.update_beacon(session_id, beacon_data)

        update_time = time.time() - start_time
        assert update_time < 10.0, f"Beacon updates took too long: {update_time:.2f}s"

        # Performance test: Statistics calculation
        start_time = time.time()
        stats = self.beacon_manager.get_statistics()
        stats_time = time.time() - start_time

        assert stats_time < 1.0, f"Statistics calculation took too long: {stats_time:.2f}s"
        assert stats["active_sessions"] == num_sessions

    @pytest.mark.security
    def test_beacon_security_validation_real(self):
        """Test security validation of beacon data and session management."""
        # Setup session
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # Test with potentially malicious beacon data
        malicious_beacon_attempts = [
            {
                "system_status": {"cpu_percent": "../../../etc/passwd"},  # Path traversal attempt
                "injection_attempt": "<script>alert('xss')</script>"
            },
            {
                "system_status": {"memory_percent": "'; DROP TABLE users; --"},  # SQL injection attempt
                "command_injection": "|rm -rf /"
            },
            {
                "system_status": {"cpu_percent": 999999999999999999999},  # Integer overflow attempt
                "buffer_overflow": "A" * 10000
            }
        ]

        # All malicious attempts should be handled without crashing
        for malicious_data in malicious_beacon_attempts:
            try:
                self.beacon_manager.update_beacon(session_id, malicious_data)
                # Should not crash the beacon manager
                assert session_id in self.beacon_manager.sessions
            except Exception as e:
                # Any exceptions should be logged, not crash the system
                assert "error" in str(e).lower() or "invalid" in str(e).lower()

        # Verify beacon manager remains functional
        valid_beacon = {
            "system_status": {"cpu_percent": 15.0, "memory_percent": 35.0},
            "timestamp": time.time()
        }
        self.beacon_manager.update_beacon(session_id, valid_beacon)

        # Should still work normally
        status = self.beacon_manager.get_session_status(session_id)
        assert status is not None
        assert status["session_id"] == session_id

    def test_error_handling_real(self):
        """Test error handling with real error scenarios."""
        # Test operations on non-existent session
        fake_session_id = "non_existent_session_123"

        # Should handle gracefully without crashing
        status = self.beacon_manager.get_session_status(fake_session_id)
        assert status is None

        history = self.beacon_manager.get_beacon_history(fake_session_id)
        assert history == []

        recommended_interval = self.beacon_manager.get_recommended_interval(fake_session_id)
        assert recommended_interval == self.beacon_manager.default_beacon_interval

        # Test beacon update on non-existent session
        self.beacon_manager.update_beacon(fake_session_id, {"test": "data"})
        # Should not create session or crash
        assert fake_session_id not in self.beacon_manager.sessions

        # Test unregistering non-existent session
        self.beacon_manager.unregister_session(fake_session_id)
        # Should not crash

        # Test with invalid beacon data
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]
        self.beacon_manager.register_session(session_id, config)

        # None beacon data
        self.beacon_manager.update_beacon(session_id, None)

        # Empty beacon data
        self.beacon_manager.update_beacon(session_id, {})

        # Session should still exist and be functional
        assert session_id in self.beacon_manager.sessions
        status = self.beacon_manager.get_session_status(session_id)
        assert status is not None

    @pytest.mark.integration
    def test_end_to_end_beacon_lifecycle_real(self):
        """Test complete end-to-end beacon lifecycle with real data flow."""
        # Phase 1: Initial session setup
        session_id = self.session_ids[0]
        config = self.test_configs["windows_endpoint"]

        self.beacon_manager.register_session(session_id, config)

        # Validate initial state
        status = self.beacon_manager.get_session_status(session_id)
        assert status["status"] == "active"
        assert status["total_beacons"] == 0

        # Phase 2: Normal beacon operations
        beacon_sequence = []
        for i in range(10):
            beacon_data = {
                "sequence": i,
                "system_status": {
                    "cpu_percent": 20.0 + (i * 2),
                    "memory_percent": 40.0 + (i * 1.5),
                    "disk_usage": 60.0 + (i * 0.5),
                    "network_io": {
                        "bytes_sent": 1000 * (i + 1),
                        "bytes_received": 1500 * (i + 1)
                    }
                },
                "security_context": {
                    "privilege_level": "system" if i % 3 == 0 else "user",
                    "process_integrity": "high" if i % 2 == 0 else "medium"
                },
                "timestamp": time.time()
            }

            self.beacon_manager.update_beacon(session_id, beacon_data)
            beacon_sequence.append(beacon_data)
            time.sleep(0.05)  # Small delay between beacons

        # Phase 3: Validate beacon processing
        status = self.beacon_manager.get_session_status(session_id)
        assert status["total_beacons"] == 10
        assert status["status"] == "active"

        history = self.beacon_manager.get_beacon_history(session_id, limit=0)
        assert len(history) == 10

        # Validate data integrity through the pipeline
        for i, historical_beacon in enumerate(history):
            original_data = beacon_sequence[i]
            stored_data = historical_beacon["data"]

            assert stored_data["sequence"] == original_data["sequence"]
            assert stored_data["system_status"]["cpu_percent"] == original_data["system_status"]["cpu_percent"]
            assert stored_data["security_context"]["privilege_level"] == original_data["security_context"]["privilege_level"]

        # Phase 4: Performance and adaptive behavior
        stats = self.beacon_manager.get_statistics()
        assert stats["total_beacons"] == 10
        assert stats["active_sessions"] == 1

        # Phase 5: Cleanup and session termination
        self.beacon_manager.unregister_session(session_id)

        # Validate complete cleanup
        assert session_id not in self.beacon_manager.sessions
        assert session_id not in self.beacon_manager.session_health
        assert session_id not in self.beacon_manager.adaptive_intervals

        final_stats = self.beacon_manager.get_statistics()
        assert final_stats["active_sessions"] == 0
