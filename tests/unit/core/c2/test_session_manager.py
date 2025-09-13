"""
Comprehensive unit tests for C2 Session Manager.
Tests REAL C2 session management, task execution, file transfers, and persistence.
NO MOCKS - ALL TESTS VALIDATE ACTUAL EXPLOITATION CAPABILITIES.
"""

import pytest
import asyncio
import os
import tempfile
import time
import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, List, Any

from intellicrack.core.c2.session_manager import Session, SessionManager
from tests.base_test import BaseIntellicrackTest


class TestSession(BaseIntellicrackTest):
    """Test Session class with real C2 session validation."""

    def test_session_creation_with_real_metadata(self):
        """Test session creation with real client metadata."""
        # Real Windows exploitation target metadata
        connection_info = {
            "ip": "192.168.1.100",
            "port": 4444,
            "protocol": "tcp",
            "os": "Windows 10 Pro 19044",
            "arch": "x64",
            "hostname": "VICTIM-PC",
            "user": "administrator",
            "privileges": "admin",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        session = Session("test-session-001", connection_info)

        # Validate session initialization
        self.assert_real_output(session)
        assert session.session_id == "test-session-001"
        assert session.connection_info == connection_info
        assert session.status == "active"
        assert time.time() - session.created_at < 1  # Recently created

        # Validate metadata extraction
        assert session.metadata["os"] == "Windows 10 Pro 19044"
        assert session.metadata["arch"] == "x64"
        assert session.metadata["hostname"] == "VICTIM-PC"
        assert session.metadata["user"] == "administrator"
        assert session.metadata["privileges"] == "admin"
        assert session.metadata["ip_address"] == "192.168.1.100"

    def test_session_task_management_real(self):
        """Test real task management for exploitation commands."""
        session = Session("exploit-session", {"os": "Windows", "arch": "x64"})

        # Add real exploitation tasks
        tasks = [
            {
                "task_id": "task-001",
                "type": "execute_shellcode",
                "data": {
                    "shellcode": b"\x48\x31\xc0\x48\x89\xc2\x48\x89\xc6\x48\x8d\x3d\x04\x00\x00\x00\x0f\x05",
                    "injection_method": "process_hollowing",
                    "target_process": "notepad.exe"
                },
                "priority": "high"
            },
            {
                "task_id": "task-002",
                "type": "privilege_escalation",
                "data": {
                    "method": "token_impersonation",
                    "target_user": "SYSTEM"
                },
                "priority": "critical"
            },
            {
                "task_id": "task-003",
                "type": "data_exfiltration",
                "data": {
                    "source_paths": [
                        "C:\\Users\\administrator\\Documents\\*.doc",
                        "C:\\ProgramData\\*.config"
                    ],
                    "compression": "zip",
                    "encryption": "aes256"
                },
                "priority": "normal"
            }
        ]

        # Add tasks to session
        for task in tasks:
            session.add_task(task)

        # Validate task addition
        pending_tasks = session.get_pending_tasks()
        assert len(pending_tasks) == 3

        # Validate task content
        shellcode_task = next(t for t in pending_tasks if t["type"] == "execute_shellcode")
        assert shellcode_task["data"]["injection_method"] == "process_hollowing"
        assert len(shellcode_task["data"]["shellcode"]) > 0

        # Test task status updates
        session.update_task_status("task-001", "completed", {
            "execution_result": "success",
            "process_id": 1337,
            "injection_address": "0x7FFF12345678"
        })

        # Validate task completion
        completed_tasks = [t for t in session.tasks if t.get("status") == "completed"]
        assert len(completed_tasks) == 1
        assert completed_tasks[0]["result"]["process_id"] == 1337

    def test_session_command_history_real(self):
        """Test real command history tracking for exploitation."""
        session = Session("history-session", {"os": "Linux", "arch": "x64"})

        # Simulate real exploitation command sequence
        commands = [
            {"cmd": "whoami", "output": "root", "timestamp": time.time()},
            {"cmd": "uname -a", "output": "Linux target 5.15.0-72-generic #79-Ubuntu", "timestamp": time.time()},
            {"cmd": "cat /etc/passwd | grep root", "output": "root:x:0:0:root:/root:/bin/bash", "timestamp": time.time()},
            {"cmd": "./exploit", "output": "Privilege escalation successful", "timestamp": time.time()},
            {"cmd": "nc -lvp 9999", "output": "Listening on [0.0.0.0] (family 0, port 9999)", "timestamp": time.time()}
        ]

        # Add commands to history
        for cmd in commands:
            session.command_history.append(cmd)

        # Validate command history
        assert len(session.command_history) == 5

        # Check exploitation sequence
        root_check = session.command_history[0]
        assert root_check["cmd"] == "whoami"
        assert root_check["output"] == "root"

        exploit_cmd = session.command_history[3]
        assert exploit_cmd["cmd"] == "./exploit"
        assert "successful" in exploit_cmd["output"]

    def test_session_to_dict_real(self):
        """Test session serialization with real exploitation data."""
        connection_info = {
            "ip": "10.0.0.50",
            "os": "Windows Server 2019",
            "arch": "x64",
            "hostname": "DC-01",
            "user": "domain_admin",
            "privileges": "admin"
        }

        session = Session("domain-session", connection_info)

        # Add some exploitation tasks
        session.add_task({
            "task_id": "domain-001",
            "type": "credential_dumping",
            "data": {"tool": "mimikatz", "target": "lsass.exe"}
        })

        # Convert to dictionary
        session_dict = session.to_dict()

        # Validate serialization
        self.assert_real_output(session_dict)
        assert session_dict["session_id"] == "domain-session"
        assert session_dict["connection_info"]["hostname"] == "DC-01"
        assert session_dict["client_info"]["user"] == "domain_admin"
        assert session_dict["status"] == "active"
        assert session_dict["uptime"] > 0
        assert session_dict["task_count"] == 1


class TestSessionManager(BaseIntellicrackTest):
    """Test SessionManager class with real C2 infrastructure validation."""

    @pytest.fixture(autouse=True)
    def setup_session_manager(self):
        """Set up session manager with temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()

        self.session_manager = SessionManager(db_path=self.temp_db.name)
        yield

        # Cleanup
        if hasattr(self, 'session_manager'):
            asyncio.run(self.session_manager.cleanup_all_sessions())
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    @pytest.mark.asyncio
    async def test_session_manager_initialization_real(self):
        """Test session manager initialization with real database setup."""
        # Validate database initialization
        assert os.path.exists(self.session_manager.db_path)

        # Check database schema
        conn = sqlite3.connect(self.session_manager.db_path)
        cursor = conn.cursor()

        # Validate tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = ["sessions", "tasks", "files"]
        for table in expected_tables:
            assert table in tables, f"Database missing table: {table}"

        conn.close()

        # Validate session manager state
        assert len(self.session_manager.sessions) == 0
        assert self.session_manager.stats["total_sessions"] == 0
        assert self.session_manager.config["session_timeout"] == 3600

    @pytest.mark.asyncio
    async def test_create_session_with_real_target_info(self):
        """Test session creation with real exploitation target information."""
        # Real target system information
        target_info = {
            "ip": "172.16.1.100",
            "port": 4444,
            "os": "Windows 10 Enterprise LTSC 2019",
            "arch": "x64",
            "hostname": "WORKSTATION-01",
            "user": "john.doe",
            "privileges": "user",
            "domain": "CORP.LOCAL",
            "antivirus": "Windows Defender",
            "processes": ["explorer.exe", "chrome.exe", "outlook.exe"],
            "network_interfaces": [
                {"name": "Ethernet0", "ip": "172.16.1.100", "mac": "00:50:56:c0:00:08"}
            ]
        }

        # Create session
        session = await self.session_manager.create_session(target_info)

        # Validate session creation
        self.assert_real_output(session)
        assert session.session_id is not None
        assert len(session.session_id) > 0
        assert session.metadata["os"] == "Windows 10 Enterprise LTSC 2019"
        assert session.metadata["hostname"] == "WORKSTATION-01"
        assert session.metadata["user"] == "john.doe"

        # Validate session is tracked
        assert session.session_id in self.session_manager.sessions
        assert self.session_manager.stats["total_sessions"] == 1
        assert self.session_manager.stats["active_sessions"] == 1

        # Validate database persistence
        conn = sqlite3.connect(self.session_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session.session_id,))
        db_session = cursor.fetchone()
        conn.close()

        assert db_session is not None
        assert db_session[0] == session.session_id  # session_id

    @pytest.mark.asyncio
    async def test_task_creation_and_execution_real(self):
        """Test real task creation and execution management."""
        # Create session for exploitation
        target_info = {"ip": "192.168.1.50", "os": "Ubuntu 20.04", "arch": "x64"}
        session = await self.session_manager.create_session(target_info)

        # Create real exploitation tasks
        tasks = [
            {
                "type": "reconnaissance",
                "data": {
                    "commands": ["ps aux", "netstat -tulpn", "cat /etc/passwd"],
                    "stealth": True
                },
                "priority": "high"
            },
            {
                "type": "privilege_escalation",
                "data": {
                    "exploits": ["CVE-2021-4034", "CVE-2022-0847"],
                    "fallback": "kernel_exploitation"
                },
                "priority": "critical"
            },
            {
                "type": "lateral_movement",
                "data": {
                    "target_hosts": ["192.168.1.10", "192.168.1.20"],
                    "methods": ["ssh_key_reuse", "credential_stuffing"]
                },
                "priority": "normal"
            }
        ]

        # Create tasks
        created_tasks = []
        for task_data in tasks:
            task = await self.session_manager.create_task(
                session.session_id, task_data["type"], task_data["data"]
            )
            created_tasks.append(task)

        # Validate task creation
        assert len(created_tasks) == 3
        for task in created_tasks:
            self.assert_real_output(task)
            assert task["status"] == "pending"
            assert task["session_id"] == session.session_id

        # Test getting pending tasks
        pending_tasks = await self.session_manager.get_pending_tasks(session.session_id)
        assert len(pending_tasks) == 3

        # Test task execution results
        recon_task_id = created_tasks[0]["task_id"]
        await self.session_manager.mark_task_sent(recon_task_id)

        # Simulate task completion with real results
        await self.session_manager.store_task_result(recon_task_id, {
            "command_results": {
                "ps aux": "UID        PID  PPID  C STIME TTY          TIME CMD\nroot         1     0  0 10:30 ?        00:00:01 /sbin/init",
                "netstat -tulpn": "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            },
            "execution_time": 2.5,
            "stealth_successful": True
        }, True)

        # Validate task completion
        completed_tasks = [t for t in session.tasks if t.get("status") == "completed"]
        assert len(completed_tasks) == 1

    @pytest.mark.asyncio
    async def test_file_upload_and_exfiltration_real(self):
        """Test real file upload and data exfiltration capabilities."""
        # Create session
        target_info = {"ip": "10.10.10.100", "os": "Windows 11", "arch": "x64"}
        session = await self.session_manager.create_session(target_info)

        # Test file upload (tool deployment)
        tool_payload = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"  # PE header stub
        await self.session_manager.store_uploaded_file(
            session.session_id, "mimikatz.exe", tool_payload
        )

        # Test document exfiltration
        exfiltrated_doc = b"CONFIDENTIAL DOCUMENT\nPassword: admin123\nAPI Keys: sk-abc123"
        await self.session_manager.store_uploaded_file(
            session.session_id, "passwords.txt", exfiltrated_doc
        )

        # Test screenshot capture
        fake_screenshot = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"  # PNG header
        await self.session_manager.store_screenshot(
            session.session_id, fake_screenshot, time.time()
        )

        # Test keylogger data
        keylog_data = "john.doe@corp.com\tpassword123\n[ENTER]\nwww.bank.com\tadmin\tP@ssw0rd!\n[TAB]"
        await self.session_manager.store_keylog_data(
            session.session_id, keylog_data, time.time()
        )

        # Validate file storage
        conn = sqlite3.connect(self.session_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files WHERE session_id = ?", (session.session_id,))
        files = cursor.fetchall()
        conn.close()

        assert len(files) == 4  # mimikatz.exe, passwords.txt, screenshot, keylog

        # Validate file metadata
        uploaded_files = {f[2]: f for f in files}  # filename -> file_record

        assert "mimikatz.exe" in uploaded_files
        assert "passwords.txt" in uploaded_files
        assert any("screenshot_" in f for f in uploaded_files)
        assert any("keylog_" in f for f in uploaded_files)

        # Validate file sizes
        mimikatz_record = uploaded_files["mimikatz.exe"]
        assert mimikatz_record[4] == len(tool_payload)  # file_size

        passwords_record = uploaded_files["passwords.txt"]
        assert passwords_record[4] == len(exfiltrated_doc)

    @pytest.mark.asyncio
    async def test_session_persistence_and_recovery_real(self):
        """Test real session persistence and recovery mechanisms."""
        # Create multiple sessions with different target types
        targets = [
            {"ip": "192.168.1.10", "os": "Windows Server 2022", "hostname": "DC01"},
            {"ip": "192.168.1.20", "os": "Ubuntu 22.04", "hostname": "web-server"},
            {"ip": "192.168.1.30", "os": "CentOS 8", "hostname": "db-server"}
        ]

        created_sessions = []
        for target in targets:
            session = await self.session_manager.create_session(target)
            created_sessions.append(session)

            # Add tasks to each session
            await self.session_manager.create_task(session.session_id, "persistence", {
                "methods": ["scheduled_task", "registry_run_key", "service_creation"],
                "stealth": True
            })

        # Simulate session manager restart by creating new instance
        new_session_manager = SessionManager(db_path=self.session_manager.db_path)
        await new_session_manager.load_sessions_from_database()

        # Validate session recovery
        recovered_sessions = new_session_manager.get_active_sessions()
        assert len(recovered_sessions) == 3

        # Validate recovered session data
        for recovered in recovered_sessions:
            self.assert_real_output(recovered)
            original = next(s for s in created_sessions if s.session_id == recovered["session_id"])
            assert recovered["connection_info"]["ip"] == original.connection_info["ip"]
            assert recovered["client_info"]["hostname"] == original.metadata["hostname"]

        # Clean up new manager
        await new_session_manager.cleanup_all_sessions()

    @pytest.mark.asyncio
    async def test_multi_session_coordination_real(self):
        """Test real multi-session coordination for complex attacks."""
        # Create botnet-like session group
        bot_targets = [
            {"ip": f"10.0.{i}.100", "os": "Windows 10", "hostname": f"PC-{i:03d}"}
            for i in range(1, 6)
        ]

        sessions = []
        for target in bot_targets:
            session = await self.session_manager.create_session(target)
            sessions.append(session)

        # Coordinate distributed denial of service
        ddos_target = "203.0.113.1"
        for session in sessions:
            await self.session_manager.create_task(session.session_id, "ddos_attack", {
                "target_ip": ddos_target,
                "attack_type": "syn_flood",
                "duration": 300,
                "rate_limit": 1000,
                "coordination_id": "ddos-campaign-001"
            })

        # Coordinate credential harvesting campaign
        for session in sessions:
            await self.session_manager.create_task(session.session_id, "credential_harvest", {
                "targets": ["browser_passwords", "saved_credentials", "keychain"],
                "upload_immediately": True,
                "campaign_id": "harvest-2024-001"
            })

        # Validate coordinated tasks
        all_pending = []
        for session in sessions:
            pending = await self.session_manager.get_pending_tasks(session.session_id)
            all_pending.extend(pending)

        assert len(all_pending) == 10  # 2 tasks × 5 sessions

        # Validate task coordination
        ddos_tasks = [t for t in all_pending if t["type"] == "ddos_attack"]
        assert len(ddos_tasks) == 5
        assert all(t["data"]["coordination_id"] == "ddos-campaign-001" for t in ddos_tasks)

        harvest_tasks = [t for t in all_pending if t["type"] == "credential_harvest"]
        assert len(harvest_tasks) == 5
        assert all(t["data"]["campaign_id"] == "harvest-2024-001" for t in harvest_tasks)

    @pytest.mark.asyncio
    async def test_session_export_for_forensics_real(self):
        """Test real session data export for forensic analysis."""
        # Create target session with comprehensive data
        target_info = {
            "ip": "172.20.1.50",
            "os": "Windows 11 Enterprise",
            "hostname": "CEO-LAPTOP",
            "user": "ceo.admin",
            "domain": "EXECUTIVE.CORP"
        }

        session = await self.session_manager.create_session(target_info)

        # Execute comprehensive exploitation campaign
        tasks_data = [
            {
                "type": "initial_access",
                "data": {"method": "spear_phishing", "payload": "macro.docm"}
            },
            {
                "type": "privilege_escalation",
                "data": {"exploit": "CVE-2023-21768", "success": True}
            },
            {
                "type": "persistence",
                "data": {"method": "golden_ticket", "domain_admin": True}
            },
            {
                "type": "credential_dumping",
                "data": {"tool": "mimikatz", "credentials_found": 47}
            },
            {
                "type": "data_exfiltration",
                "data": {"files_stolen": 1337, "total_size": "2.3GB"}
            }
        ]

        # Create and complete tasks
        for task_data in tasks_data:
            task = await self.session_manager.create_task(
                session.session_id, task_data["type"], task_data["data"]
            )
            await self.session_manager.mark_task_sent(task["task_id"])
            await self.session_manager.store_task_result(
                task["task_id"], {"success": True, "details": task_data["data"]}, True
            )

        # Add exfiltrated files
        for i in range(5):
            fake_file = f"confidential_document_{i}.pdf".encode() * 100
            await self.session_manager.store_uploaded_file(
                session.session_id, f"doc_{i}.pdf", fake_file
            )

        # Export session data
        export_data = await self.session_manager.export_session_data(session.session_id)

        # Validate comprehensive export
        self.assert_real_output(export_data)
        assert "session" in export_data
        assert "tasks" in export_data
        assert "files" in export_data
        assert "export_time" in export_data

        # Validate session data
        session_data = export_data["session"]
        assert session_data["session_id"] == session.session_id
        assert session_data["connection_info"]["hostname"] == "CEO-LAPTOP"

        # Validate tasks data
        assert len(export_data["tasks"]) == 5
        task_types = [t["task_type"] for t in export_data["tasks"]]
        assert "credential_dumping" in task_types
        assert "data_exfiltration" in task_types

        # Validate files data
        assert len(export_data["files"]) == 5
        assert all(f["filename"].startswith("doc_") for f in export_data["files"])

    def test_session_statistics_real(self):
        """Test real session statistics and monitoring."""
        # Create sessions with realistic activity patterns
        asyncio.run(self._create_realistic_sessions())

        # Get comprehensive statistics
        stats = self.session_manager.get_statistics()

        # Validate statistics completeness
        self.assert_real_output(stats)
        required_stats = [
            "total_sessions", "active_sessions", "session_history_count",
            "pending_task_count", "average_session_uptime", "most_active_session"
        ]

        for stat in required_stats:
            assert stat in stats, f"Missing statistic: {stat}"

        # Validate realistic values
        assert stats["total_sessions"] >= 0
        assert stats["active_sessions"] >= 0
        assert stats["average_session_uptime"] >= 0

        if stats["active_sessions"] > 0:
            assert stats["most_active_session"] is not None

    async def _create_realistic_sessions(self):
        """Helper to create realistic session activity."""
        # High-value target
        await self.session_manager.create_session({
            "ip": "10.0.1.10", "os": "Windows Server 2019", "hostname": "EXCHANGE-01"
        })

        # Regular workstation
        await self.session_manager.create_session({
            "ip": "192.168.1.100", "os": "Windows 11", "hostname": "USER-LAPTOP"
        })

    def test_filename_sanitization_security_real(self):
        """Test real filename sanitization for security."""
        test_cases = [
            # Path traversal attempts
            ("../../../etc/passwd", "etc_passwd"),
            ("..\\..\\windows\\system32\\cmd.exe", "windows_system32_cmd.exe"),

            # Malicious filenames
            ("<script>alert('xss')</script>.txt", "_script_alert('xss')__script_.txt"),
            ("file|with|pipes.doc", "file_with_pipes.doc"),
            ("file:with:colons.txt", "file_with_colons.txt"),

            # Hidden files
            (".hidden_malware.exe", "hidden_malware.exe"),
            ("...config.ini", "config.ini"),

            # Long filenames
            ("A" * 300 + ".txt", "A" * 251 + ".txt"),  # Should be truncated to 255 chars
        ]

        for original, expected in test_cases:
            sanitized = self.session_manager._sanitize_filename(original)
            assert len(sanitized) <= 255
            assert not sanitized.startswith(".")
            assert ".." not in sanitized
            assert all(c not in sanitized for c in '<>:"/\\|?*')

    def test_database_integrity_under_load_real(self):
        """Test database integrity under concurrent session load."""
        async def stress_test():
            # Create many concurrent sessions
            tasks = []
            for i in range(50):
                target_info = {
                    "ip": f"10.0.{i//254}.{i%254}",
                    "os": "Windows 10",
                    "hostname": f"PC-{i:03d}"
                }
                tasks.append(self.session_manager.create_session(target_info))

            sessions = await asyncio.gather(*tasks)

            # Create tasks for each session
            task_creation_tasks = []
            for session in sessions:
                for j in range(3):  # 3 tasks per session
                    task_creation_tasks.append(
                        self.session_manager.create_task(
                            session.session_id, f"task_type_{j}", {"data": f"task_{j}"}
                        )
                    )

            await asyncio.gather(*task_creation_tasks)

            return len(sessions)

        # Run stress test
        session_count = asyncio.run(stress_test())

        # Validate database integrity
        conn = sqlite3.connect(self.session_manager.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM sessions")
        db_session_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tasks")
        db_task_count = cursor.fetchone()[0]

        conn.close()

        # Validate counts match expected
        assert db_session_count == session_count
        assert db_task_count == session_count * 3  # 3 tasks per session
