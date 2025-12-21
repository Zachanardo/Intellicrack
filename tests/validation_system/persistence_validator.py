"""
Persistence Validator for Phase 3 validation.
Tests software persistence and stability after bypass application.
"""

import os
import time
import hashlib
import logging
import subprocess
import winreg
from pathlib import Path
from typing import List
from dataclasses import dataclass
from datetime import datetime
import psutil

from commercial_binary_manager import CommercialBinaryManager

logger = logging.getLogger(__name__)


@dataclass
class PersistenceTestResult:
    """Result of a persistence validation test."""
    software_name: str
    binary_path: str
    binary_hash: str
    test_type: str
    test_start_time: str
    test_end_time: str
    test_duration_seconds: float
    software_remained_functional: bool
    reboot_persistence: bool
    time_based_persistence: bool
    bypass_persistence_valid: bool
    error_messages: list[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class PersistenceValidator:
    """Validates software persistence and stability after bypass application."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.logs_dir = self.base_dir / "logs"
        self.reports_dir = self.base_dir / "reports"
        self.temp_dir = self.base_dir / "temp"

        # Create required directories
        for directory in [self.logs_dir, self.reports_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True)

        self.binary_manager = CommercialBinaryManager(base_dir)

        logger.info("PersistenceValidator initialized")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def test_long_term_execution(self, binary_path: str, software_name: str, duration_hours: int = 1) -> PersistenceTestResult:
        """
        Test software stability during long-term execution.
        """
        logger.info(f"Starting long-term execution test for {software_name} (duration: {duration_hours}h)")

        test_start_time = datetime.now().isoformat()
        binary_hash = self._calculate_hash(binary_path)
        error_messages = []
        software_remained_functional = False
        bypass_persistence_valid = False

        try:
            process = subprocess.Popen(
                [binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )

            initial_pid = process.pid
            logger.info(f"Started {software_name} with PID {initial_pid}")

            test_duration_minutes = duration_hours * 60
            check_interval = min(30, test_duration_minutes / 10)
            checks_performed = 0
            successful_checks = 0

            start_time = time.time()
            end_time = start_time + (test_duration_minutes * 60)

            while time.time() < end_time:
                try:
                    psutil_proc = psutil.Process(initial_pid)
                    if psutil_proc.is_running() and psutil_proc.status() != psutil.STATUS_ZOMBIE:
                        cpu_percent = psutil_proc.cpu_percent()
                        memory_info = psutil_proc.memory_info()

                        memory_mb = memory_info.rss / 1024 / 1024
                        logger.info(f"Check {checks_performed + 1}: PID {initial_pid} - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB")

                        if cpu_percent < 95 and memory_info.rss < (2 * 1024 * 1024 * 1024):
                            successful_checks += 1

                        checks_performed += 1
                    else:
                        error_messages.append(f"Process {initial_pid} stopped running during test")
                        break

                except psutil.NoSuchProcess:
                    error_messages.append(f"Process {initial_pid} no longer exists")
                    break
                except psutil.AccessDenied:
                    error_messages.append(f"Access denied monitoring process {initial_pid}")
                    break
                except Exception as e:
                    error_messages.append(f"Error monitoring process: {str(e)}")
                    break

                time.sleep(check_interval * 60)

            try:
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            except Exception as e:
                error_messages.append(f"Error terminating process: {str(e)}")

            if checks_performed > 0:
                success_rate = successful_checks / checks_performed
                software_remained_functional = success_rate >= 0.8
                bypass_persistence_valid = success_rate >= 0.9
                logger.info(f"Long-term test completed: {successful_checks}/{checks_performed} checks passed ({success_rate:.1%})")
            else:
                error_messages.append("No successful process checks performed")

        except FileNotFoundError:
            error_messages.append(f"Binary not found: {binary_path}")
        except PermissionError:
            error_messages.append(f"Permission denied executing: {binary_path}")
        except Exception as e:
            error_messages.append(f"Error starting process: {str(e)}")

        test_end_time = datetime.now().isoformat()
        test_duration = (datetime.fromisoformat(test_end_time) - datetime.fromisoformat(test_start_time)).total_seconds()

        return PersistenceTestResult(
            software_name=software_name,
            binary_path=binary_path,
            binary_hash=binary_hash,
            test_type="long_term_execution",
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            test_duration_seconds=test_duration,
            software_remained_functional=software_remained_functional,
            reboot_persistence=False,
            time_based_persistence=False,
            bypass_persistence_valid=bypass_persistence_valid,
            error_messages=error_messages,
        )

    def test_reboot_persistence(self, binary_path: str, software_name: str) -> PersistenceTestResult:
        """
        Test bypass persistence across system reboots.
        """
        logger.info(f"Starting reboot persistence test for {software_name}")

        test_start_time = datetime.now().isoformat()
        binary_hash = self._calculate_hash(binary_path)
        error_messages = []
        software_remained_functional = False
        reboot_persistence = False
        bypass_persistence_valid = False

        persistence_indicators = {
            'registry_keys': [],
            'startup_entries': [],
            'file_modifications': [],
            'service_installations': []
        }

        try:
            logger.info("Checking registry persistence indicators")
            reg_keys_to_check = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
            ]

            for hkey, subkey in reg_keys_to_check:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        i = 0
                        while True:
                            try:
                                name, value, reg_type = winreg.EnumValue(key, i)
                                if software_name.lower() in name.lower() or software_name.lower() in str(value).lower():
                                    persistence_indicators['registry_keys'].append({
                                        'hkey': hkey,
                                        'subkey': subkey,
                                        'name': name,
                                        'value': str(value)
                                    })
                                    logger.info(f"Found registry persistence: {name} = {value}")
                                i += 1
                            except OSError:
                                break
                except FileNotFoundError:
                    continue
                except PermissionError:
                    error_messages.append(f"Access denied reading registry key: {subkey}")
                except Exception as e:
                    error_messages.append(f"Error reading registry: {str(e)}")

            logger.info("Checking startup folder persistence")
            startup_folders = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.environ.get('ALLUSERSPROFILE', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            ]

            for folder in startup_folders:
                if os.path.exists(folder):
                    try:
                        for item in os.listdir(folder):
                            item_path = os.path.join(folder, item)
                            if os.path.isfile(item_path) and software_name.lower() in item.lower():
                                persistence_indicators['startup_entries'].append(item_path)
                                logger.info(f"Found startup file: {item_path}")
                    except PermissionError:
                        error_messages.append(f"Access denied reading startup folder: {folder}")
                    except Exception as e:
                        error_messages.append(f"Error reading startup folder: {str(e)}")

            logger.info("Checking file system modifications")
            binary_dir = os.path.dirname(binary_path)
            modification_patterns = [
                os.path.join(binary_dir, '*patch*'),
                os.path.join(binary_dir, '*crack*'),
                os.path.join(binary_dir, '*bypass*'),
                os.path.join(binary_dir, '*.dll.bak'),
                os.path.join(binary_dir, '*.exe.orig')
            ]

            for pattern in modification_patterns:
                try:
                    import glob
                    matches = glob.glob(pattern)
                    for match in matches:
                        persistence_indicators['file_modifications'].append(match)
                        logger.info(f"Found file modification: {match}")
                except Exception as e:
                    error_messages.append(f"Error checking file pattern {pattern}: {str(e)}")

            logger.info("Checking Windows services")
            try:
                result = subprocess.run(
                    ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SERVICE_NAME:' in line:
                            service_name = line.split(':', 1)[1].strip()
                            if software_name.lower() in service_name.lower():
                                persistence_indicators['service_installations'].append(service_name)
                                logger.info(f"Found related service: {service_name}")
                else:
                    error_messages.append("Failed to query Windows services")
            except Exception as e:
                error_messages.append(f"Error checking services: {str(e)}")

            logger.info("Simulating reboot scenario by checking file locks and process dependencies")
            try:
                process = subprocess.Popen(
                    [binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )

                time.sleep(2)

                if process.poll() is None:
                    software_remained_functional = True
                    logger.info("Software started successfully after persistence check")

                    process.terminate()
                    process.wait(timeout=10)
                else:
                    error_messages.append("Software failed to start after persistence check")

            except Exception as e:
                error_messages.append(f"Error testing post-reboot functionality: {str(e)}")

            total_persistence_indicators = (
                len(persistence_indicators['registry_keys']) +
                len(persistence_indicators['startup_entries']) +
                len(persistence_indicators['file_modifications']) +
                len(persistence_indicators['service_installations'])
            )

            if total_persistence_indicators > 0:
                reboot_persistence = True
                bypass_persistence_valid = software_remained_functional
                logger.info(f"Found {total_persistence_indicators} persistence indicators")
            else:
                logger.info("No persistence indicators found - bypass may not persist across reboots")

        except Exception as e:
            error_messages.append(f"Error during reboot persistence test: {str(e)}")

        test_end_time = datetime.now().isoformat()
        test_duration = (datetime.fromisoformat(test_end_time) - datetime.fromisoformat(test_start_time)).total_seconds()

        result = PersistenceTestResult(
            software_name=software_name,
            binary_path=binary_path,
            binary_hash=binary_hash,
            test_type="reboot_persistence",
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            test_duration_seconds=test_duration,
            software_remained_functional=software_remained_functional,
            reboot_persistence=reboot_persistence,
            time_based_persistence=False,
            bypass_persistence_valid=bypass_persistence_valid,
            error_messages=error_messages
        )

        return result

    def test_time_based_persistence(self, binary_path: str, software_name: str) -> PersistenceTestResult:
        """
        Test bypass persistence across time-based challenges.
        """
        logger.info(f"Starting time-based persistence test for {software_name}")

        test_start_time = datetime.now().isoformat()
        binary_hash = self._calculate_hash(binary_path)
        error_messages = []
        software_remained_functional = False
        time_based_persistence = False
        bypass_persistence_valid = False

        time_test_results = {
            'normal_time_test': False,
            'future_time_test': False,
            'past_time_test': False,
            'system_clock_independence': False
        }

        try:
            logger.info("Testing software at normal system time")
            try:
                process = subprocess.Popen(
                    [binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )

                time.sleep(2)

                if process.poll() is None:
                    time_test_results['normal_time_test'] = True
                    logger.info("Software functional at normal system time")

                    process.terminate()
                    process.wait(timeout=5)
                else:
                    error_messages.append("Software failed to start at normal system time")

            except Exception as e:
                error_messages.append(f"Error testing normal time: {str(e)}")

            logger.info("Testing time manipulation scenarios using PowerShell")

            time_scenarios = [
                {
                    'name': 'future_time_test',
                    'description': 'Testing software with future date (30 days ahead)',
                    'powershell_cmd': '(Get-Date).AddDays(30).ToString("MM/dd/yyyy HH:mm:ss")'
                },
                {
                    'name': 'past_time_test',
                    'description': 'Testing software with past date (30 days ago)',
                    'powershell_cmd': '(Get-Date).AddDays(-30).ToString("MM/dd/yyyy HH:mm:ss")'
                }
            ]

            for scenario in time_scenarios:
                logger.info(scenario['description'])

                try:
                    get_time_result = subprocess.run(
                        ['powershell', '-Command', scenario['powershell_cmd']],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=10
                    )

                    if get_time_result.returncode == 0:
                        target_time = get_time_result.stdout.strip()
                        logger.info(f"Target time for test: {target_time}")

                        set_time_cmd = f'Set-Date "{target_time}"'

                        ps_cmd = f'Start-Process powershell -ArgumentList "-Command", "{set_time_cmd}" -Verb RunAs -Wait'
                        set_time_result = subprocess.run(
                            ['powershell', '-Command', ps_cmd],
                            capture_output=True,
                            text=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=15
                        )

                        if set_time_result.returncode == 0:
                            logger.info(f"Successfully set system time for {scenario['name']}")

                            try:
                                test_process = subprocess.Popen(
                                    [binary_path],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                                )

                                time.sleep(3)

                                if test_process.poll() is None:
                                    time_test_results[scenario['name']] = True
                                    logger.info(f"Software functional during {scenario['name']}")

                                    test_process.terminate()
                                    test_process.wait(timeout=5)
                                else:
                                    error_messages.append(f"Software failed during {scenario['name']}")

                            except Exception as e:
                                error_messages.append(f"Error testing {scenario['name']}: {str(e)}")

                            logger.info("Restoring original system time")
                            restore_cmd = 'w32tm /resync'
                            subprocess.run(
                                ['powershell', '-Command', f'Start-Process cmd -ArgumentList "/c", "{restore_cmd}" -Verb RunAs -Wait'],
                                capture_output=True,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                timeout=10
                            )
                        else:
                            error_messages.append(f"Failed to set system time for {scenario['name']} - may need admin privileges")
                    else:
                        error_messages.append(f"Failed to calculate time for {scenario['name']}")

                except subprocess.TimeoutExpired:
                    error_messages.append(f"Timeout during {scenario['name']}")
                except Exception as e:
                    error_messages.append(f"Error in {scenario['name']}: {str(e)}")

            logger.info("Testing system clock independence using process environment")
            try:
                env = os.environ.copy()
                future_timestamp = str(int(time.time()) + (30 * 24 * 60 * 60))
                env['FORCE_EPOCH_TIME'] = future_timestamp

                env_process = subprocess.Popen(
                    [binary_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )

                time.sleep(2)

                if env_process.poll() is None:
                    time_test_results['system_clock_independence'] = True
                    logger.info("Software shows resilience to environment time manipulation")

                    env_process.terminate()
                    env_process.wait(timeout=5)
                else:
                    logger.info("Software may be affected by environment time variables")

            except Exception as e:
                error_messages.append(f"Error testing environment time manipulation: {str(e)}")

            logger.info("Analyzing registry and file system for time-based artifacts")
            try:
                reg_keys_to_check = [
                    (winreg.HKEY_CURRENT_USER, r"Software"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE")
                ]

                time_related_keys = []
                for hkey, subkey_root in reg_keys_to_check:
                    try:
                        software_key_path = f"{subkey_root}\\{software_name}"
                        with winreg.OpenKey(hkey, software_key_path) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, reg_type = winreg.EnumValue(key, i)
                                    time_keywords = ['install', 'first', 'last', 'expire', 'trial', 'date', 'time']
                                    if any(keyword in name.lower() for keyword in time_keywords):
                                        time_related_keys.append({
                                            'key': software_key_path,
                                            'name': name,
                                            'value': str(value)
                                        })
                                        logger.info(f"Found time-related registry entry: {name} = {value}")
                                    i += 1
                                except OSError:
                                    break
                    except (FileNotFoundError, PermissionError):
                        continue
                    except Exception as e:
                        error_messages.append(f"Error checking registry for time artifacts: {str(e)}")

                if time_related_keys:
                    logger.info(f"Found {len(time_related_keys)} time-related registry entries")

            except Exception as e:
                error_messages.append(f"Error analyzing time-based artifacts: {str(e)}")

            successful_tests = sum(time_test_results.values())
            total_tests = len(time_test_results)

            if successful_tests > 0:
                software_remained_functional = True

            if successful_tests >= 2:
                time_based_persistence = True

            if successful_tests >= 3:
                bypass_persistence_valid = True

            logger.info(f"Time-based persistence test results: {successful_tests}/{total_tests} tests passed")

        except Exception as e:
            error_messages.append(f"Critical error during time-based persistence test: {str(e)}")

        test_end_time = datetime.now().isoformat()
        test_duration = (datetime.fromisoformat(test_end_time) - datetime.fromisoformat(test_start_time)).total_seconds()

        return PersistenceTestResult(
            software_name=software_name,
            binary_path=binary_path,
            binary_hash=binary_hash,
            test_type="time_based_persistence",
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            test_duration_seconds=test_duration,
            software_remained_functional=software_remained_functional,
            reboot_persistence=False,
            time_based_persistence=time_based_persistence,
            bypass_persistence_valid=bypass_persistence_valid,
            error_messages=error_messages,
        )

    def validate_persistence(self, binary_path: str, software_name: str) -> list[PersistenceTestResult]:
        """
        Run all persistence validation tests for a software binary.
        """
        logger.info(f"Starting full persistence validation for {software_name}")

        # Test 1: Long-term execution
        long_term_result = self.test_long_term_execution(binary_path, software_name)
        results = [long_term_result]
        # Test 2: Reboot persistence
        reboot_result = self.test_reboot_persistence(binary_path, software_name)
        results.append(reboot_result)

        # Test 3: Time-based persistence
        time_based_result = self.test_time_based_persistence(binary_path, software_name)
        results.append(time_based_result)

        logger.info(f"Completed full persistence validation for {software_name}")
        return results

    def validate_all_persistence(self) -> list[PersistenceTestResult]:
        """
        Run persistence validation on all available binaries.
        """
        logger.info("Starting persistence validation for all binaries")

        all_results = []
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                if binary_path and os.path.exists(binary_path):
                    logger.info(f"Testing persistence for {software_name}")
                    results = self.validate_persistence(binary_path, software_name)
                    all_results.extend(results)
                else:
                    # Create failed results for each test type
                    all_results.extend(
                        PersistenceTestResult(
                            software_name=software_name,
                            binary_path=binary_path or "",
                            binary_hash="",
                            test_type=test_type,
                            test_start_time=datetime.now().isoformat(),
                            test_end_time=datetime.now().isoformat(),
                            test_duration_seconds=0,
                            software_remained_functional=False,
                            reboot_persistence=False,
                            time_based_persistence=False,
                            bypass_persistence_valid=False,
                            error_messages=[f"Binary not found: {binary_path}"],
                        )
                        for test_type in [
                            "long_term_execution",
                            "reboot_persistence",
                            "time_based_persistence",
                        ]
                    )
            except Exception as e:
                # Create failed results for each test type
                for test_type in ["long_term_execution", "reboot_persistence", "time_based_persistence"]:
                    all_results.append(PersistenceTestResult(
                        software_name=binary.get("software_name", "Unknown"),
                        binary_path=binary.get("file_path", ""),
                        binary_hash="",
                        test_type=test_type,
                        test_start_time=datetime.now().isoformat(),
                        test_end_time=datetime.now().isoformat(),
                        test_duration_seconds=0,
                        software_remained_functional=False,
                        reboot_persistence=False,
                        time_based_persistence=False,
                        bypass_persistence_valid=False,
                        error_messages=[str(e)]
                    ))

        logger.info(f"Completed persistence validation for {len(all_results)} tests")
        return all_results
