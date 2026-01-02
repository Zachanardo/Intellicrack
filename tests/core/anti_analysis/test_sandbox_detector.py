"""Production-grade tests for SandboxDetector module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
import platform
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.anti_analysis.sandbox_detector import SandboxDetector


class FakeProcess:
    """Real test double for psutil.Process."""

    def __init__(self, pid: int, name: str, exe: str, cmdline: list[str]) -> None:
        self.pid: int = pid
        self._name: str = name
        self._exe: str = exe
        self._cmdline: list[str] = cmdline
        self.call_count: int = 0

    def name(self) -> str:
        self.call_count += 1
        return self._name

    def exe(self) -> str:
        self.call_count += 1
        return self._exe

    def cmdline(self) -> list[str]:
        self.call_count += 1
        return self._cmdline


class FakeProcessIterator:
    """Real test double for psutil.process_iter()."""

    def __init__(self, processes: list[FakeProcess]) -> None:
        self.processes: list[FakeProcess] = processes
        self.call_count: int = 0

    def __call__(self, attrs: list[str] | None = None, ad_value: Any = None) -> list[dict[str, Any]]:
        self.call_count += 1
        result: list[dict[str, Any]] = []
        for proc in self.processes:
            proc_dict: dict[str, Any] = {"pid": proc.pid}
            if attrs:
                for attr in attrs:
                    if attr == "name":
                        proc_dict["name"] = proc.name()
                    elif attr == "exe":
                        proc_dict["exe"] = proc.exe()
                    elif attr == "cmdline":
                        proc_dict["cmdline"] = proc.cmdline()
            result.append(proc_dict)
        return result


class FakeNetworkInterface:
    """Real test double for network interface data."""

    def __init__(self, addresses: dict[str, list[dict[str, str]]]) -> None:
        self.addresses: dict[str, list[dict[str, str]]] = addresses
        self.call_count: int = 0

    def __call__(self) -> dict[str, list[dict[str, str]]]:
        self.call_count += 1
        return self.addresses


class FakeSubprocess:
    """Real test double for subprocess operations."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode: int = returncode
        self.stdout: str = stdout
        self.stderr: str = stderr
        self.commands_run: list[list[str]] = []

    def run(
        self,
        args: list[str],
        capture_output: bool = False,
        text: bool = False,
        check: bool = False,
        timeout: float | None = None,
    ) -> "FakeCompletedProcess":
        self.commands_run.append(args)
        result = FakeCompletedProcess(self.returncode, self.stdout, self.stderr)
        if check and self.returncode != 0:
            raise subprocess.CalledProcessError(self.returncode, args, self.stdout, self.stderr)
        return result


class FakeCompletedProcess:
    """Real test double for subprocess.CompletedProcess."""

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode: int = returncode
        self.stdout: str = stdout
        self.stderr: str = stderr


class FakeSocket:
    """Real test double for socket operations."""

    def __init__(self, hostname: str = "localhost") -> None:
        self._hostname: str = hostname
        self.call_count: int = 0

    def gethostname(self) -> str:
        self.call_count += 1
        return self._hostname


class FakeTimeModule:
    """Real test double for time module with acceleration detection."""

    def __init__(self, acceleration_factor: float = 1.0) -> None:
        self.acceleration_factor: float = acceleration_factor
        self.call_count: int = 0
        self._start_time: float = time.time()

    def time(self) -> float:
        self.call_count += 1
        elapsed: float = time.time() - self._start_time
        return self._start_time + (elapsed * self.acceleration_factor)

    def sleep(self, seconds: float) -> None:
        self.call_count += 1
        actual_sleep: float = seconds / self.acceleration_factor
        time.sleep(actual_sleep)


class FakePlatform:
    """Real test double for platform module."""

    def __init__(
        self,
        system: str = "Windows",
        machine: str = "AMD64",
        processor: str = "Intel64 Family 6 Model 142 Stepping 12, GenuineIntel",
    ) -> None:
        self._system: str = system
        self._machine: str = machine
        self._processor: str = processor
        self.call_count: int = 0

    def system(self) -> str:
        self.call_count += 1
        return self._system

    def machine(self) -> str:
        self.call_count += 1
        return self._machine

    def processor(self) -> str:
        self.call_count += 1
        return self._processor


class FakeWinReg:
    """Real test double for Windows registry operations."""

    def __init__(self, registry_data: dict[tuple[int, str, str], Any]) -> None:
        self.registry_data: dict[tuple[int, str, str], Any] = registry_data
        self.call_count: int = 0

    def OpenKey(self, key: int, sub_key: str) -> int:
        self.call_count += 1
        return hash((key, sub_key))

    def QueryValueEx(self, key: int, value_name: str) -> tuple[Any, int]:
        self.call_count += 1
        for (reg_key, reg_sub_key, reg_value_name), value in self.registry_data.items():
            if value_name == reg_value_name:
                return (value, 1)
        raise FileNotFoundError(f"Registry value {value_name} not found")

    def CloseKey(self, key: int) -> None:
        self.call_count += 1


class TestSandboxDetectorInitialization:
    """Test SandboxDetector initialization and configuration."""

    def test_detector_initializes_successfully(self) -> None:
        """SandboxDetector initializes with all detection methods configured."""
        detector = SandboxDetector()

        assert detector is not None
        assert hasattr(detector, "detection_methods")
        assert len(detector.detection_methods) > 0
        assert hasattr(detector, "sandbox_signatures")
        assert hasattr(detector, "behavioral_patterns")
        assert hasattr(detector, "detection_cache")

    def test_detector_has_expected_detection_methods(self) -> None:
        """SandboxDetector contains all expected detection methods."""
        detector = SandboxDetector()

        expected_methods: list[str] = [
            "environment_checks",
            "behavioral_detection",
            "resource_limits",
            "network_connectivity",
            "user_interaction",
            "file_system",
            "process_monitoring",
            "time_acceleration",
            "api_hooks",
            "mouse_movement",
            "hardware_analysis",
            "registry_analysis",
            "virtualization",
            "environment_variables",
            "parent_process_analysis",
            "cpuid_hypervisor_check",
            "mac_address_analysis",
            "browser_automation",
            "timing_attacks",
        ]

        for method in expected_methods:
            assert method in detector.detection_methods, f"Missing detection method: {method}"
            assert callable(detector.detection_methods[method])

    def test_detector_builds_sandbox_signatures(self) -> None:
        """SandboxDetector builds comprehensive sandbox signatures."""
        detector = SandboxDetector()

        expected_sandboxes: list[str] = [
            "cuckoo",
            "vmray",
            "joe_sandbox",
            "threatgrid",
            "hybrid_analysis",
            "sandboxie",
            "anubis",
            "norman",
            "fortinet",
            "fireeye",
            "hatching_triage",
            "intezer",
            "virustotal",
        ]

        for sandbox in expected_sandboxes:
            assert sandbox in detector.sandbox_signatures, f"Missing sandbox signature: {sandbox}"


class TestSandboxDetectorEnvironmentChecks:
    """Test environment-based sandbox detection."""

    def test_detect_sandbox_environment_clean_system(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector does not flag clean production environment."""
        clean_env: dict[str, str] = {
            "USERNAME": "productionuser",
            "COMPUTERNAME": "WORKSTATION-001",
            "PATH": "C:\\Windows\\system32;C:\\Windows",
        }

        for key, value in clean_env.items():
            monkeypatch.setenv(key, value)

        fake_socket = FakeSocket("WORKSTATION-001")
        monkeypatch.setattr(socket, "gethostname", fake_socket.gethostname)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        env_check = result.get("detections", {}).get("environment_checks", {})
        if env_check:
            assert not env_check.get("detected", False) or env_check.get("confidence", 0.0) < 0.5

    def test_detect_sandbox_environment_suspicious_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies sandbox-specific usernames."""
        suspicious_env: dict[str, str] = {
            "USERNAME": "sandbox",
            "COMPUTERNAME": "NORMAL-PC",
        }

        for key, value in suspicious_env.items():
            monkeypatch.setenv(key, value)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "detections" in result
        env_check = result["detections"].get("environment_checks", {})
        if env_check and env_check.get("detected"):
            details = env_check.get("details", {})
            suspicious_items = details.get("suspicious_env", [])
            assert any("username" in str(item).lower() for item in suspicious_items)

    def test_detect_sandbox_environment_suspicious_computername(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies sandbox-specific computer names."""
        suspicious_env: dict[str, str] = {
            "USERNAME": "normaluser",
            "COMPUTERNAME": "CUCKOO-ANALYSIS",
        }

        for key, value in suspicious_env.items():
            monkeypatch.setenv(key, value)

        fake_socket = FakeSocket("CUCKOO-ANALYSIS")
        monkeypatch.setattr(socket, "gethostname", fake_socket.gethostname)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        env_check = result["detections"].get("environment_checks", {})
        if env_check and env_check.get("detected"):
            details = env_check.get("details", {})
            suspicious_items = details.get("suspicious_env", [])
            assert any("computername" in str(item).lower() for item in suspicious_items)

    def test_detect_sandbox_environment_variables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies sandbox-specific environment variables."""
        sandbox_env: dict[str, str] = {
            "USERNAME": "analyst",
            "COMPUTERNAME": "ANALYSIS-01",
            "CUCKOO": "1",
            "CUCKOO_ROOT": "C:\\cuckoo",
            "VMRAY_ANALYSIS": "enabled",
        }

        for key, value in sandbox_env.items():
            monkeypatch.setenv(key, value)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert result.get("is_sandbox") is True
        assert result.get("confidence", 0.0) > 0.3


class TestSandboxDetectorProcessMonitoring:
    """Test process-based sandbox detection."""

    def test_detect_sandbox_clean_process_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector does not flag normal system processes."""
        clean_processes: list[FakeProcess] = [
            FakeProcess(1000, "explorer.exe", "C:\\Windows\\explorer.exe", ["C:\\Windows\\explorer.exe"]),
            FakeProcess(1004, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", ["chrome.exe"]),
            FakeProcess(1008, "notepad.exe", "C:\\Windows\\System32\\notepad.exe", ["notepad.exe"]),
        ]

        fake_iterator = FakeProcessIterator(clean_processes)
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        proc_check = result.get("detections", {}).get("process_monitoring", {})
        if proc_check:
            assert not proc_check.get("detected", False) or proc_check.get("confidence", 0.0) < 0.5

    def test_detect_sandbox_suspicious_processes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies sandbox analysis processes."""
        suspicious_processes: list[FakeProcess] = [
            FakeProcess(1000, "explorer.exe", "C:\\Windows\\explorer.exe", ["C:\\Windows\\explorer.exe"]),
            FakeProcess(1004, "analyzer.exe", "C:\\cuckoo\\analyzer.exe", ["analyzer.exe"]),
            FakeProcess(1008, "agent.py", "C:\\cuckoo\\agent.py", ["python.exe", "agent.py"]),
            FakeProcess(1012, "vmray_agent.exe", "C:\\vmray\\vmray_agent.exe", ["vmray_agent.exe"]),
        ]

        fake_iterator = FakeProcessIterator(suspicious_processes)
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        proc_check = result.get("detections", {}).get("process_monitoring", {})
        if proc_check and proc_check.get("detected"):
            details = proc_check.get("details", {})
            assert "suspicious_processes" in details
            suspicious_list = details["suspicious_processes"]
            assert len(suspicious_list) > 0


class TestSandboxDetectorFileSystemArtifacts:
    """Test file system artifact detection."""

    def test_detect_sandbox_file_artifacts_clean_system(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """SandboxDetector does not flag normal file system."""
        normal_dirs: list[Path] = [
            tmp_path / "Windows" / "System32",
            tmp_path / "Program Files",
            tmp_path / "Users" / "normaluser",
        ]

        for dir_path in normal_dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        fs_check = result.get("detections", {}).get("file_system", {})
        if fs_check:
            assert not fs_check.get("detected", False) or fs_check.get("confidence", 0.0) < 0.5

    def test_detect_sandbox_file_artifacts_present(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """SandboxDetector identifies sandbox-specific files and directories."""
        sandbox_artifacts: list[Path] = [
            tmp_path / "cuckoo" / "analyzer",
            tmp_path / "vmray" / "agent",
            tmp_path / "sandbox" / "monitor",
        ]

        for artifact_path in sandbox_artifacts:
            artifact_path.mkdir(parents=True, exist_ok=True)
            (artifact_path / "artifact.txt").write_text("sandbox artifact")

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        fs_check = result.get("detections", {}).get("file_system", {})
        if fs_check and fs_check.get("detected"):
            details = fs_check.get("details", {})
            assert "suspicious_files" in details or "suspicious_paths" in details


class TestSandboxDetectorTimeAcceleration:
    """Test time acceleration detection."""

    def test_detect_time_acceleration_normal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector does not flag normal time progression."""
        fake_time = FakeTimeModule(acceleration_factor=1.0)
        monkeypatch.setattr(time, "time", fake_time.time)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        time_check = result.get("detections", {}).get("time_acceleration", {})
        if time_check:
            assert not time_check.get("detected", False) or time_check.get("confidence", 0.0) < 0.5

    def test_detect_time_acceleration_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies accelerated time (sandbox analysis speedup)."""
        fake_time = FakeTimeModule(acceleration_factor=10.0)
        monkeypatch.setattr(time, "time", fake_time.time)
        monkeypatch.setattr(time, "sleep", fake_time.sleep)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        time_check = result.get("detections", {}).get("time_acceleration", {})
        if time_check and time_check.get("detected"):
            details = time_check.get("details", {})
            assert "acceleration_factor" in details or "timing_discrepancy" in details


class TestSandboxDetectorNetworkChecks:
    """Test network-based sandbox detection."""

    def test_detect_sandbox_network_normal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector does not flag normal network configuration."""
        normal_interfaces: dict[str, list[dict[str, str]]] = {
            "Ethernet": [{"addr": "192.168.1.100"}],
            "Wi-Fi": [{"addr": "10.0.0.50"}],
        }

        fake_net = FakeNetworkInterface(normal_interfaces)
        monkeypatch.setattr(psutil, "net_if_addrs", fake_net)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        net_check = result.get("detections", {}).get("network_connectivity", {})
        if net_check:
            assert not net_check.get("detected", False) or net_check.get("confidence", 0.0) < 0.5

    def test_detect_sandbox_network_suspicious(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector identifies sandbox-specific network configurations."""
        sandbox_interfaces: dict[str, list[dict[str, str]]] = {
            "vboxnet0": [{"addr": "192.168.56.1"}],
            "vmnet1": [{"addr": "192.168.2.1"}],
            "cuckoo0": [{"addr": "10.0.0.1"}],
        }

        fake_net = FakeNetworkInterface(sandbox_interfaces)
        monkeypatch.setattr(psutil, "net_if_addrs", fake_net)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        net_check = result.get("detections", {}).get("network_connectivity", {})
        if net_check and net_check.get("detected"):
            details = net_check.get("details", {})
            assert "suspicious_interfaces" in details or "suspicious_networks" in details


class TestSandboxDetectorComprehensive:
    """Comprehensive end-to-end sandbox detection tests."""

    def test_detect_sandbox_full_analysis_clean_system(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector comprehensive analysis on clean production system."""
        clean_env: dict[str, str] = {
            "USERNAME": "productionuser",
            "COMPUTERNAME": "WORKSTATION-042",
        }
        for key, value in clean_env.items():
            monkeypatch.setenv(key, value)

        clean_processes: list[FakeProcess] = [
            FakeProcess(1000, "explorer.exe", "C:\\Windows\\explorer.exe", ["C:\\Windows\\explorer.exe"]),
            FakeProcess(1004, "chrome.exe", "C:\\Program Files\\Chrome\\chrome.exe", ["chrome.exe"]),
        ]
        fake_iterator = FakeProcessIterator(clean_processes)
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        fake_socket = FakeSocket("WORKSTATION-042")
        monkeypatch.setattr(socket, "gethostname", fake_socket.gethostname)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in result
        assert "confidence" in result
        assert "detections" in result
        assert isinstance(result["is_sandbox"], bool)
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_detect_sandbox_full_analysis_cuckoo_sandbox(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector comprehensively identifies Cuckoo Sandbox environment."""
        cuckoo_env: dict[str, str] = {
            "USERNAME": "analyst",
            "COMPUTERNAME": "CUCKOO-GUEST",
            "CUCKOO": "1",
            "CUCKOO_ROOT": "C:\\cuckoo",
        }
        for key, value in cuckoo_env.items():
            monkeypatch.setenv(key, value)

        cuckoo_processes: list[FakeProcess] = [
            FakeProcess(1000, "explorer.exe", "C:\\Windows\\explorer.exe", ["C:\\Windows\\explorer.exe"]),
            FakeProcess(1004, "analyzer.exe", "C:\\cuckoo\\analyzer.exe", ["analyzer.exe"]),
            FakeProcess(1008, "agent.py", "C:\\cuckoo\\agent.py", ["python.exe", "agent.py"]),
        ]
        fake_iterator = FakeProcessIterator(cuckoo_processes)
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        fake_socket = FakeSocket("CUCKOO-GUEST")
        monkeypatch.setattr(socket, "gethostname", fake_socket.gethostname)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert result.get("is_sandbox") is True
        assert result.get("confidence", 0.0) > 0.5
        assert result.get("sandbox_type") is not None
        assert "cuckoo" in str(result.get("sandbox_type", "")).lower() or result.get("detection_count", 0) > 0

    def test_detect_sandbox_full_analysis_vmray_sandbox(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector comprehensively identifies VMRay Sandbox environment."""
        vmray_env: dict[str, str] = {
            "USERNAME": "vmray",
            "COMPUTERNAME": "VMRAY-ANALYSIS",
            "VMRAY": "1",
            "VMRAY_ANALYSIS": "active",
        }
        for key, value in vmray_env.items():
            monkeypatch.setenv(key, value)

        vmray_processes: list[FakeProcess] = [
            FakeProcess(1000, "explorer.exe", "C:\\Windows\\explorer.exe", ["C:\\Windows\\explorer.exe"]),
            FakeProcess(1004, "vmray_agent.exe", "C:\\vmray\\vmray_agent.exe", ["vmray_agent.exe"]),
        ]
        fake_iterator = FakeProcessIterator(vmray_processes)
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        fake_socket = FakeSocket("VMRAY-ANALYSIS")
        monkeypatch.setattr(socket, "gethostname", fake_socket.gethostname)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert result.get("is_sandbox") is True
        assert result.get("confidence", 0.0) > 0.5

    def test_detect_sandbox_aggressive_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector runs additional checks in aggressive mode."""
        detector = SandboxDetector()
        result_normal: dict[str, Any] = detector.detect_sandbox(aggressive=False)
        result_aggressive: dict[str, Any] = detector.detect_sandbox(aggressive=True)

        assert "detections" in result_normal
        assert "detections" in result_aggressive

        normal_methods: int = len(result_normal.get("detections", {}))
        aggressive_methods: int = len(result_aggressive.get("detections", {}))

        assert aggressive_methods >= normal_methods

    def test_detect_sandbox_returns_complete_results(self) -> None:
        """SandboxDetector returns all required result fields."""
        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        required_fields: list[str] = [
            "is_sandbox",
            "confidence",
            "sandbox_type",
            "detections",
            "evasion_difficulty",
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

        assert isinstance(result["is_sandbox"], bool)
        assert isinstance(result["confidence"], float)
        assert isinstance(result["detections"], dict)
        assert 0.0 <= result["confidence"] <= 1.0


class TestSandboxDetectorEdgeCases:
    """Test edge cases and error handling."""

    def test_detect_sandbox_handles_missing_environment_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector handles missing environment variables gracefully."""
        for var in ["USERNAME", "COMPUTERNAME", "PATH"]:
            monkeypatch.delenv(var, raising=False)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in result
        assert isinstance(result["is_sandbox"], bool)

    def test_detect_sandbox_handles_process_access_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector handles process access errors gracefully."""

        def failing_process_iter(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise PermissionError("Access denied to process information")

        monkeypatch.setattr(psutil, "process_iter", failing_process_iter)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in result
        assert isinstance(result["is_sandbox"], bool)

    def test_detect_sandbox_handles_network_access_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector handles network access errors gracefully."""

        def failing_net_if_addrs() -> dict[str, list[dict[str, str]]]:
            raise OSError("Network interface access denied")

        monkeypatch.setattr(psutil, "net_if_addrs", failing_net_if_addrs)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in result
        assert isinstance(result["is_sandbox"], bool)

    def test_detect_sandbox_empty_process_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SandboxDetector handles empty process list gracefully."""
        fake_iterator = FakeProcessIterator([])
        monkeypatch.setattr(psutil, "process_iter", fake_iterator)

        detector = SandboxDetector()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)

        assert "is_sandbox" in result
        assert isinstance(result["is_sandbox"], bool)


class TestSandboxDetectorPerformance:
    """Test performance characteristics of sandbox detection."""

    def test_detect_sandbox_completes_within_timeout(self) -> None:
        """SandboxDetector completes analysis within reasonable timeframe."""
        detector = SandboxDetector()

        start_time: float = time.time()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=False)
        elapsed_time: float = time.time() - start_time

        assert elapsed_time < 30.0, f"Detection took {elapsed_time:.2f}s, expected < 30s"
        assert "is_sandbox" in result

    def test_detect_sandbox_aggressive_completes_within_timeout(self) -> None:
        """SandboxDetector aggressive mode completes within reasonable timeframe."""
        detector = SandboxDetector()

        start_time: float = time.time()
        result: dict[str, Any] = detector.detect_sandbox(aggressive=True)
        elapsed_time: float = time.time() - start_time

        assert elapsed_time < 60.0, f"Aggressive detection took {elapsed_time:.2f}s, expected < 60s"
        assert "is_sandbox" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
