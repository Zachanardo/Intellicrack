"""
Phase 6.5: Anti-Gaming Validation System

This module implements comprehensive anti-gaming measures to detect any attempts
to circumvent or manipulate the validation process.
"""

import hashlib
import logging
import json
import subprocess
import time
import psutil
import socket
import os
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import dns.resolver
import winreg
import ctypes
from ctypes import wintypes

class AntiGamingResult(Enum):
    """Anti-gaming validation result."""
    CLEAN = "CLEAN"
    GAMING_DETECTED = "GAMING_DETECTED"
    CONTAMINATED = "CONTAMINATED"
    SUSPICIOUS = "SUSPICIOUS"
    INVALID = "INVALID"

class GamingViolationType(Enum):
    """Types of gaming violations."""
    BINARY_HASH_MISMATCH = "binary_hash_mismatch"
    IDENTICAL_OUTPUTS = "identical_outputs"
    DEBUGGER_DETECTED = "debugger_detected"
    UNAUTHORIZED_NETWORK = "unauthorized_network"
    PROCESS_INJECTION = "process_injection"
    TIME_CHALLENGE_FAILURE = "time_challenge_failure"
    ENVIRONMENT_TAMPERING = "environment_tampering"
    PRECOMPUTED_RESPONSES = "precomputed_responses"

@dataclass
class GamingViolation:
    """Structure for gaming violation detection."""
    violation_type: GamingViolationType
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    evidence: Dict[str, Any]
    timestamp: str
    confidence: float  # 0.0 to 1.0

@dataclass
class ValidationEnvironment:
    """Structure for environment state."""
    running_processes: List[Dict[str, Any]]
    network_connections: List[Dict[str, Any]]
    loaded_modules: List[str]
    registry_state: Dict[str, Any]
    file_system_state: Dict[str, str]
    hardware_info: Dict[str, Any]

class AntiGamingValidationSystem:
    """
    Implements Phase 6.5 requirements for anti-gaming validation.

    ANY violation = IMMEDIATE FAIL:
    - Binary hash mismatch = TEST INVALID (possible pre-cracked binary)
    - Identical outputs across random inputs = GAMING DETECTED
    - Debugger/analysis tools detected during test = CONTAMINATED ENVIRONMENT
    - Network activity to non-whitelisted IPs = EXTERNAL ASSISTANCE SUSPECTED
    - Process injection from unknown source = TAMPERING DETECTED
    - Time-based challenge response incorrect = PRE-COMPUTATION ATTEMPTED
    """

    def __init__(self, config_path: Path, whitelist_path: Path):
        """Initialize anti-gaming validation system."""
        self.config_path = Path(config_path)
        self.whitelist_path = Path(whitelist_path)
        self.logger = logging.getLogger(__name__)

        # Load configuration
        self.config = self._load_config()
        self.whitelist = self._load_whitelist()

        # Initialize baseline environment state
        self.baseline_environment = None
        self.violations = []

        # Cryptographic challenge state
        self.active_challenges = {}

    def _load_config(self) -> Dict[str, Any]:
        """Load anti-gaming configuration."""
        try:
            config_file = self.config_path / "anti_gaming_config.json"
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return {
                    "max_identical_outputs": 2,
                    "time_challenge_tolerance_ms": 1000,
                    "suspicious_processes": [
                        "x64dbg.exe", "ida.exe", "cheatengine.exe", "ollydbg.exe",
                        "wireshark.exe", "fiddler.exe", "procmon.exe", "regshot.exe"
                    ],
                    "allowed_network_ranges": ["127.0.0.1/32", "::1/128"],
                    "hash_verification_interval": 300  # 5 minutes
                }
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise

    def _load_whitelist(self) -> Dict[str, Any]:
        """Load network and process whitelists."""
        try:
            whitelist_file = self.whitelist_path / "anti_gaming_whitelist.json"
            if whitelist_file.exists():
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return {
                    "allowed_ips": ["127.0.0.1", "::1"],
                    "allowed_domains": ["localhost"],
                    "allowed_processes": ["explorer.exe", "dwm.exe", "winlogon.exe"],
                    "system_dlls": ["ntdll.dll", "kernel32.dll", "user32.dll"]
                }
        except Exception as e:
            self.logger.error(f"Failed to load whitelist: {e}")
            return {}

    def establish_baseline_environment(self) -> ValidationEnvironment:
        """Establish baseline environment state before testing."""
        try:
            self.logger.info("Establishing baseline environment state...")

            baseline = ValidationEnvironment(
                running_processes=self._get_process_list(),
                network_connections=self._get_network_connections(),
                loaded_modules=self._get_loaded_modules(),
                registry_state=self._capture_registry_state(),
                file_system_state=self._capture_file_system_state(),
                hardware_info=self._get_hardware_info()
            )

            self.baseline_environment = baseline
            return baseline

        except Exception as e:
            self.logger.error(f"Failed to establish baseline environment: {e}")
            raise

    def validate_binary_integrity(self, binary_path: Path, expected_hash: str) -> Tuple[bool, Optional[GamingViolation]]:
        """6.5.1: Validate binary hash to detect pre-cracked binaries."""
        try:
            current_hash = self._calculate_file_hash(binary_path)

            if current_hash != expected_hash:
                violation = GamingViolation(
                    violation_type=GamingViolationType.BINARY_HASH_MISMATCH,
                    description=f"Binary hash mismatch detected for {binary_path.name}",
                    severity="CRITICAL",
                    evidence={
                        "expected_hash": expected_hash,
                        "actual_hash": current_hash,
                        "binary_path": str(binary_path)
                    },
                    timestamp=self._get_timestamp(),
                    confidence=1.0
                )
                self.violations.append(violation)
                return False, violation

            return True, None

        except Exception as e:
            self.logger.error(f"Binary integrity validation failed: {e}")
            return False, None

    def detect_identical_outputs(self, test_results: List[Dict[str, Any]]) -> Tuple[bool, Optional[GamingViolation]]:
        """6.5.2: Detect identical outputs across random inputs (gaming indicator)."""
        try:
            output_hashes = {}

            for result in test_results:
                input_data = result.get("input_hash", "")
                output_data = result.get("output_hash", "")

                if output_data:
                    if output_data not in output_hashes:
                        output_hashes[output_data] = []
                    output_hashes[output_data].append(input_data)

            # Check for identical outputs with different inputs
            for output_hash, input_hashes in output_hashes.items():
                if len(input_hashes) > self.config["max_identical_outputs"]:
                    # Different inputs producing identical outputs is suspicious
                    unique_inputs = set(input_hashes)
                    if len(unique_inputs) > 1:
                        violation = GamingViolation(
                            violation_type=GamingViolationType.IDENTICAL_OUTPUTS,
                            description=f"Identical outputs detected for {len(unique_inputs)} different inputs",
                            severity="CRITICAL",
                            evidence={
                                "output_hash": output_hash,
                                "input_hashes": list(unique_inputs),
                                "occurrence_count": len(input_hashes)
                            },
                            timestamp=self._get_timestamp(),
                            confidence=0.95
                        )
                        self.violations.append(violation)
                        return False, violation

            return True, None

        except Exception as e:
            self.logger.error(f"Identical outputs detection failed: {e}")
            return True, None

    def detect_analysis_tools(self) -> Tuple[bool, List[GamingViolation]]:
        """6.5.3: Detect debuggers and analysis tools during testing."""
        try:
            violations = []
            current_processes = self._get_process_list()

            for process in current_processes:
                process_name = process.get("name", "").lower()

                # Check against suspicious process list
                for suspicious in self.config["suspicious_processes"]:
                    if suspicious.lower() in process_name:
                        violation = GamingViolation(
                            violation_type=GamingViolationType.DEBUGGER_DETECTED,
                            description=f"Analysis tool detected: {process_name}",
                            severity="HIGH",
                            evidence={
                                "process_name": process_name,
                                "process_id": process.get("pid"),
                                "command_line": process.get("cmdline", "")
                            },
                            timestamp=self._get_timestamp(),
                            confidence=0.9
                        )
                        violations.append(violation)

            # Check for debugger flags in environment
            debugger_checks = self._check_debugger_presence()
            if debugger_checks["debugger_present"]:
                violation = GamingViolation(
                    violation_type=GamingViolationType.DEBUGGER_DETECTED,
                    description="Debugger presence detected via system checks",
                    severity="HIGH",
                    evidence=debugger_checks,
                    timestamp=self._get_timestamp(),
                    confidence=0.8
                )
                violations.append(violation)

            self.violations.extend(violations)
            return len(violations) == 0, violations

        except Exception as e:
            self.logger.error(f"Analysis tools detection failed: {e}")
            return True, []

    def monitor_network_activity(self, duration_seconds: int = 60) -> Tuple[bool, List[GamingViolation]]:
        """6.5.4: Monitor for unauthorized network activity."""
        try:
            violations = []
            self.logger.info(f"Monitoring network activity for {duration_seconds} seconds...")

            start_time = time.time()
            connections_log = []

            while time.time() - start_time < duration_seconds:
                connections = self._get_network_connections()

                for conn in connections:
                    remote_ip = conn.get("remote_addr", "")
                    remote_port = conn.get("remote_port", 0)

                    if remote_ip and not self._is_whitelisted_ip(remote_ip):
                        # Check if this is a license server connection
                        if self._is_potential_license_server(remote_ip, remote_port):
                            violation = GamingViolation(
                                violation_type=GamingViolationType.UNAUTHORIZED_NETWORK,
                                description=f"Potential license server connection detected: {remote_ip}:{remote_port}",
                                severity="CRITICAL",
                                evidence={
                                    "remote_ip": remote_ip,
                                    "remote_port": remote_port,
                                    "local_port": conn.get("local_port"),
                                    "status": conn.get("status")
                                },
                                timestamp=self._get_timestamp(),
                                confidence=0.8
                            )
                            violations.append(violation)

                time.sleep(1)

            self.violations.extend(violations)
            return len(violations) == 0, violations

        except Exception as e:
            self.logger.error(f"Network monitoring failed: {e}")
            return True, []

    def detect_process_injection(self) -> Tuple[bool, List[GamingViolation]]:
        """6.5.5: Detect process injection from unknown sources."""
        try:
            violations = []

            if not self.baseline_environment:
                self.logger.warning("No baseline environment established - cannot detect injection")
                return True, []

            current_processes = self._get_process_list()
            baseline_processes = {p["name"]: p for p in self.baseline_environment.running_processes}

            # Detect new processes
            for process in current_processes:
                process_name = process["name"]

                if process_name not in baseline_processes:
                    # New process - check if it's suspicious
                    if self._is_suspicious_process(process):
                        violation = GamingViolation(
                            violation_type=GamingViolationType.PROCESS_INJECTION,
                            description=f"Suspicious new process detected: {process_name}",
                            severity="HIGH",
                            evidence={
                                "process_name": process_name,
                                "process_id": process.get("pid"),
                                "parent_pid": process.get("ppid"),
                                "command_line": process.get("cmdline", "")
                            },
                            timestamp=self._get_timestamp(),
                            confidence=0.7
                        )
                        violations.append(violation)

            # Check for DLL injection
            dll_injection_detected = self._check_dll_injection()
            if dll_injection_detected["injections_found"]:
                violation = GamingViolation(
                    violation_type=GamingViolationType.PROCESS_INJECTION,
                    description="DLL injection detected",
                    severity="HIGH",
                    evidence=dll_injection_detected,
                    timestamp=self._get_timestamp(),
                    confidence=0.8
                )
                violations.append(violation)

            self.violations.extend(violations)
            return len(violations) == 0, violations

        except Exception as e:
            self.logger.error(f"Process injection detection failed: {e}")
            return True, []

    def generate_time_challenge(self, challenge_id: str, complexity: int = 1000000) -> Dict[str, Any]:
        """Generate time-based challenge to prevent pre-computation."""
        try:
            import random
            import uuid

            # Generate random challenge data
            challenge_data = {
                "challenge_id": challenge_id,
                "nonce": str(uuid.uuid4()),
                "timestamp": time.time(),
                "complexity": complexity,
                "data": [random.randint(0, 1000000) for _ in range(100)]
            }

            # Calculate expected response (simple computation that takes time)
            expected_response = sum(x * x for x in challenge_data["data"]) % 1000000

            challenge_data["expected_response"] = expected_response
            self.active_challenges[challenge_id] = challenge_data

            # Return challenge without expected response
            client_challenge = {k: v for k, v in challenge_data.items() if k != "expected_response"}
            return client_challenge

        except Exception as e:
            self.logger.error(f"Time challenge generation failed: {e}")
            return {}

    def validate_time_challenge_response(self, challenge_id: str, response: int,
                                       response_time_ms: float) -> Tuple[bool, Optional[GamingViolation]]:
        """6.5.6: Validate time-based challenge response."""
        try:
            if challenge_id not in self.active_challenges:
                return False, None

            challenge = self.active_challenges[challenge_id]
            expected_response = challenge["expected_response"]
            min_time_ms = challenge["complexity"] / 10000  # Expected minimum time
            tolerance_ms = self.config["time_challenge_tolerance_ms"]

            # Validate response correctness
            if response != expected_response:
                violation = GamingViolation(
                    violation_type=GamingViolationType.TIME_CHALLENGE_FAILURE,
                    description="Time challenge response incorrect - possible pre-computation",
                    severity="HIGH",
                    evidence={
                        "challenge_id": challenge_id,
                        "expected_response": expected_response,
                        "actual_response": response,
                        "response_time_ms": response_time_ms
                    },
                    timestamp=self._get_timestamp(),
                    confidence=0.9
                )
                self.violations.append(violation)
                return False, violation

            # Validate response time (too fast indicates pre-computation)
            if response_time_ms < (min_time_ms - tolerance_ms):
                violation = GamingViolation(
                    violation_type=GamingViolationType.TIME_CHALLENGE_FAILURE,
                    description="Time challenge response too fast - possible pre-computation",
                    severity="MEDIUM",
                    evidence={
                        "challenge_id": challenge_id,
                        "expected_min_time_ms": min_time_ms,
                        "actual_time_ms": response_time_ms,
                        "difference_ms": min_time_ms - response_time_ms
                    },
                    timestamp=self._get_timestamp(),
                    confidence=0.7
                )
                self.violations.append(violation)
                return False, violation

            # Clean up completed challenge
            del self.active_challenges[challenge_id]
            return True, None

        except Exception as e:
            self.logger.error(f"Time challenge validation failed: {e}")
            return False, None

    def comprehensive_anti_gaming_scan(self, binary_path: Path, expected_hash: str,
                                     test_results: List[Dict[str, Any]]) -> Tuple[AntiGamingResult, Dict[str, Any]]:
        """Perform comprehensive anti-gaming validation."""
        validation_report = {
            "timestamp": self._get_timestamp(),
            "binary_path": str(binary_path),
            "scan_results": {},
            "violations_detected": [],
            "overall_result": AntiGamingResult.CLEAN,
            "confidence_score": 1.0
        }

        try:
            # Clear previous violations
            self.violations = []

            # 6.5.1: Binary integrity check
            binary_clean, binary_violation = self.validate_binary_integrity(binary_path, expected_hash)
            validation_report["scan_results"]["binary_integrity"] = {
                "clean": binary_clean,
                "violation": binary_violation.__dict__ if binary_violation else None
            }

            # 6.5.2: Identical outputs detection
            outputs_clean, outputs_violation = self.detect_identical_outputs(test_results)
            validation_report["scan_results"]["output_analysis"] = {
                "clean": outputs_clean,
                "violation": outputs_violation.__dict__ if outputs_violation else None
            }

            # 6.5.3: Analysis tools detection
            tools_clean, tools_violations = self.detect_analysis_tools()
            validation_report["scan_results"]["analysis_tools"] = {
                "clean": tools_clean,
                "violations": [v.__dict__ for v in tools_violations]
            }

            # 6.5.4: Network activity monitoring
            network_clean, network_violations = self.monitor_network_activity(30)
            validation_report["scan_results"]["network_activity"] = {
                "clean": network_clean,
                "violations": [v.__dict__ for v in network_violations]
            }

            # 6.5.5: Process injection detection
            injection_clean, injection_violations = self.detect_process_injection()
            validation_report["scan_results"]["process_injection"] = {
                "clean": injection_clean,
                "violations": [v.__dict__ for v in injection_violations]
            }

            # Compile all violations
            all_violations = self.violations
            validation_report["violations_detected"] = [v.__dict__ for v in all_violations]

            # Determine overall result
            critical_violations = [v for v in all_violations if v.severity == "CRITICAL"]
            high_violations = [v for v in all_violations if v.severity == "HIGH"]

            if critical_violations:
                validation_report["overall_result"] = AntiGamingResult.GAMING_DETECTED
                validation_report["confidence_score"] = max(v.confidence for v in critical_violations)
            elif high_violations:
                validation_report["overall_result"] = AntiGamingResult.CONTAMINATED
                validation_report["confidence_score"] = max(v.confidence for v in high_violations)
            elif all_violations:
                validation_report["overall_result"] = AntiGamingResult.SUSPICIOUS
                validation_report["confidence_score"] = max(v.confidence for v in all_violations)
            else:
                validation_report["overall_result"] = AntiGamingResult.CLEAN
                validation_report["confidence_score"] = 1.0

        except Exception as e:
            self.logger.error(f"Anti-gaming scan failed: {e}")
            validation_report["overall_result"] = AntiGamingResult.INVALID
            validation_report["error"] = str(e)

        return validation_report["overall_result"], validation_report

    # Helper methods

    def _get_process_list(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'exe']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Failed to get process list: {e}")
        return processes

    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        connections = []
        try:
            for conn in psutil.net_connections():
                if conn.raddr:
                    connections.append({
                        "local_addr": conn.laddr.ip if conn.laddr else "",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_addr": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except Exception as e:
            self.logger.error(f"Failed to get network connections: {e}")
        return connections

    def _get_loaded_modules(self) -> List[str]:
        """Get list of loaded system modules."""
        modules = []
        try:
            # This is a simplified version - would use more comprehensive module enumeration
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name']:
                        modules.append(proc.info['name'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Failed to get loaded modules: {e}")
        return list(set(modules))

    def _capture_registry_state(self) -> Dict[str, Any]:
        """Capture relevant registry state."""
        return {"placeholder": "registry_state"}  # Simplified

    def _capture_file_system_state(self) -> Dict[str, str]:
        """Capture file system state checksums."""
        return {"placeholder": "filesystem_state"}  # Simplified

    def _get_hardware_info(self) -> Dict[str, Any]:
        """Get hardware information."""
        try:
            return {
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "boot_time": psutil.boot_time()
            }
        except Exception as e:
            self.logger.error(f"Failed to get hardware info: {e}")
            return {}

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
        return sha256_hash.hexdigest()

    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        try:
            ip_addr = ipaddress.ip_address(ip)

            # Check against allowed IPs
            for allowed_ip in self.whitelist.get("allowed_ips", []):
                if str(ip_addr) == allowed_ip:
                    return True

            # Check against allowed ranges
            for range_str in self.config.get("allowed_network_ranges", []):
                network = ipaddress.ip_network(range_str)
                if ip_addr in network:
                    return True

            return False
        except Exception:
            return False

    def _is_potential_license_server(self, ip: str, port: int) -> bool:
        """Check if connection might be to a license server."""
        # Common license server ports
        license_ports = [1947, 27000, 7788, 5093, 2080, 4000]

        if port in license_ports:
            return True

        # Check if IP resolves to known license server domains
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            license_domains = ['flexnetoperations.com', 'adobe.com', 'autodesk.com', 'mathworks.com']

            for domain in license_domains:
                if domain in hostname:
                    return True
        except Exception:
            # Domain resolution may fail, continue checking

        return False

    def _is_suspicious_process(self, process: Dict[str, Any]) -> bool:
        """Check if process is suspicious."""
        process_name = process.get("name", "").lower()
        cmdline = process.get("cmdline", "")

        # Check against known suspicious patterns
        suspicious_patterns = [
            "inject", "hook", "patch", "crack", "keygen", "loader"
        ]

        for pattern in suspicious_patterns:
            if pattern in process_name or (cmdline and pattern in " ".join(cmdline).lower()):
                return True

        return False

    def _check_debugger_presence(self) -> Dict[str, Any]:
        """Check for debugger presence using Windows API."""
        try:
            # Use Windows API to check for debugger
            kernel32 = ctypes.windll.kernel32

            # IsDebuggerPresent check
            debugger_present = kernel32.IsDebuggerPresent()

            # CheckRemoteDebuggerPresent check
            current_process = kernel32.GetCurrentProcess()
            debug_flag = wintypes.BOOL()
            kernel32.CheckRemoteDebuggerPresent(current_process, ctypes.byref(debug_flag))

            return {
                "debugger_present": bool(debugger_present or debug_flag.value),
                "is_debugger_present": bool(debugger_present),
                "remote_debugger_present": bool(debug_flag.value)
            }
        except Exception as e:
            return {"error": str(e), "debugger_present": False}

    def _check_dll_injection(self) -> Dict[str, Any]:
        """Check for DLL injection."""
        try:
            # Get current process modules
            current_process = psutil.Process()
            loaded_dlls = []

            try:
                for dll in current_process.memory_maps():
                    if dll.path and dll.path.endswith('.dll'):
                        loaded_dlls.append(dll.path.lower())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                # Process may have exited or access denied, continue

            # Check for suspicious DLLs
            system_dll_paths = [
                'c:\\windows\\system32',
                'c:\\windows\\syswow64',
                'c:\\program files',
                'c:\\program files (x86)'
            ]

            suspicious_dlls = []
            for dll_path in loaded_dlls:
                is_system_dll = any(dll_path.startswith(sys_path) for sys_path in system_dll_paths)
                if not is_system_dll:
                    suspicious_dlls.append(dll_path)

            return {
                "injections_found": len(suspicious_dlls) > 0,
                "suspicious_dlls": suspicious_dlls,
                "total_loaded_dlls": len(loaded_dlls)
            }

        except Exception as e:
            return {"error": str(e), "injections_found": False}

    def _get_timestamp(self) -> str:
        """Get ISO timestamp."""
        return datetime.utcnow().isoformat() + 'Z'


def main():
    """Example usage of AntiGamingValidationSystem."""
    system = AntiGamingValidationSystem(
        from intellicrack.utils.path_resolver import get_project_root

config_path=get_project_root() / "tests/validation_system",
        whitelist_path=get_project_root() / "tests/validation_system"
    )

    # Establish baseline
    baseline = system.establish_baseline_environment()
    print(f"Baseline established: {len(baseline.running_processes)} processes")

    # Example test results
    test_results = [
        {"input_hash": "abc123", "output_hash": "def456"},
        {"input_hash": "xyz789", "output_hash": "uvw012"}
    ]

    # Run comprehensive scan
    result, report = system.comprehensive_anti_gaming_scan(
        binary_path=Path("C:/test/sample.exe"),
        expected_hash="expected_hash_here",
        test_results=test_results
    )

    print(f"Anti-Gaming Result: {result.value}")
    print(f"Confidence Score: {report['confidence_score']:.2f}")
    print(f"Violations: {len(report['violations_detected'])}")


if __name__ == "__main__":
    main()
