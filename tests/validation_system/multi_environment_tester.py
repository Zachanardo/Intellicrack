#!/usr/bin/env python3
"""
Multi-Environment Testing Matrix for Intellicrack Validation System.

This module provides production-ready multi-environment testing capabilities
to ensure Intellicrack works correctly across diverse hardware and software
configurations including bare metal, VMs, containers, and cloud environments.
"""

import json
import logging
import os
import platform
import queue
import subprocess
import sys
import time
import traceback
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from intellicrack.handlers.wmi_handler import wmi
from tests.validation_system.environment_validator import HardwareValidator

logger = logging.getLogger(__name__)

# Import our environment validator
sys.path.insert(0, r'C:\Intellicrack')

@dataclass
class TestEnvironment:
    """Configuration for a test environment."""

    name: str
    environment_type: str  # bare_metal, vm, container, cloud
    platform_os: str  # windows, linux, macos
    architecture: str  # x86_64, arm64
    requirements: Dict[str, Any]
    validation_criteria: Dict[str, Any]
    setup_commands: List[str] = field(default_factory=list)
    teardown_commands: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 3
    tags: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Result from testing in an environment."""

    environment_name: str
    test_name: str
    passed: bool
    execution_time: float
    output: str
    error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class EnvironmentDetector:
    """Detects current environment characteristics."""

    def __init__(self):
        self.wmi_client = wmi.WMI() if platform.system() == 'Windows' else None

    def detect_container(self) -> Dict[str, Any]:
        """
        Detect if running in a container environment.

        Returns:
            Container detection results
        """
        container_indicators = {
            'is_container': False,
            'container_type': None,
            'indicators': []
        }

        # Check for Docker
        if os.path.exists('/.dockerenv'):
            container_indicators['is_container'] = True
            container_indicators['container_type'] = 'docker'
            container_indicators['indicators'].append('/.dockerenv file exists')

        # Check for containerd
        if os.path.exists('/run/containerd'):
            container_indicators['is_container'] = True
            container_indicators['container_type'] = 'containerd'
            container_indicators['indicators'].append('/run/containerd exists')

        # Check cgroup for container signatures
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content:
                    container_indicators['is_container'] = True
                    container_indicators['container_type'] = 'docker'
                    container_indicators['indicators'].append('Docker in cgroup')
                elif 'lxc' in cgroup_content:
                    container_indicators['is_container'] = True
                    container_indicators['container_type'] = 'lxc'
                    container_indicators['indicators'].append('LXC in cgroup')
        except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        # Check for Kubernetes
        if os.path.exists('/var/run/secrets/kubernetes.io'):
            container_indicators['is_container'] = True
            container_indicators['container_type'] = 'kubernetes'
            container_indicators['indicators'].append('Kubernetes secrets directory exists')

        return container_indicators

    def detect_cloud_provider(self) -> Dict[str, Any]:
        """
        Detect cloud provider if running in cloud.

        Returns:
            Cloud provider detection results
        """
        cloud_info = {
            'is_cloud': False,
            'provider': None,
            'instance_type': None,
            'region': None,
            'metadata': {}
        }

        # Try AWS metadata service
        try:
            with urllib.request.urlopen(
                'http://169.254.169.254/latest/meta-data/', timeout=1
            ) as response:
                if response.status == 200:
                    cloud_info['is_cloud'] = True
                    cloud_info['provider'] = 'aws'
                    # Get instance type
                    with urllib.request.urlopen(
                        'http://169.254.169.254/latest/meta-data/instance-type', timeout=1
                    ) as r:
                        cloud_info['instance_type'] = r.read().decode()
                    # Get region
                    with urllib.request.urlopen(
                        'http://169.254.169.254/latest/meta-data/placement/region', timeout=1
                    ) as r:
                        cloud_info['region'] = r.read().decode()
        except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        # Try Azure metadata service
        if not cloud_info['is_cloud']:
            try:
                req = urllib.request.Request(
                    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                    headers={'Metadata': 'true'}
                )
                with urllib.request.urlopen(req, timeout=1) as response:  # noqa: S310
                    if response.status == 200:
                        cloud_info['is_cloud'] = True
                        cloud_info['provider'] = 'azure'
                        metadata = json.loads(response.read())
                        cloud_info['instance_type'] = metadata.get('compute', {}).get('vmSize')
                        cloud_info['region'] = metadata.get('compute', {}).get('location')
            except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        # Try GCP metadata service
        if not cloud_info['is_cloud']:
            try:
                req = urllib.request.Request(
                    'http://metadata.google.internal/computeMetadata/v1/',
                    headers={'Metadata-Flavor': 'Google'}
                )
                with urllib.request.urlopen(req, timeout=1) as response:  # noqa: S310
                    if response.status == 200:
                        cloud_info['is_cloud'] = True
                        cloud_info['provider'] = 'gcp'
            except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        # Windows-specific cloud detection via WMI
        if platform.system() == 'Windows' and self.wmi_client:
            for cs in self.wmi_client.Win32_ComputerSystem():
                if cs.Manufacturer:
                    manufacturer = cs.Manufacturer.lower()
                    if 'microsoft corporation' in manufacturer:
                        cloud_info['is_cloud'] = True
                        cloud_info['provider'] = 'azure'
                    elif 'amazon' in manufacturer:
                        cloud_info['is_cloud'] = True
                        cloud_info['provider'] = 'aws'
                    elif 'google' in manufacturer:
                        cloud_info['is_cloud'] = True
                        cloud_info['provider'] = 'gcp'

        return cloud_info

    def detect_wsl(self) -> Dict[str, Any]:
        """
        Detect Windows Subsystem for Linux.

        Returns:
            WSL detection results
        """
        wsl_info = {
            'is_wsl': False,
            'version': None,
            'distro': None,
            'kernel': None
        }

        # Check for WSL-specific files
        if os.path.exists('/proc/sys/fs/binfmt_misc/WSLInterop'):
            wsl_info['is_wsl'] = True
            wsl_info['version'] = 2  # WSL2 has this file

        # Check kernel version for Microsoft
        try:
            kernel_version = platform.release()
            if 'microsoft' in kernel_version.lower():
                wsl_info['is_wsl'] = True
                wsl_info['kernel'] = kernel_version
                # Determine WSL version
                if 'WSL2' in kernel_version:
                    wsl_info['version'] = 2
                else:
                    wsl_info['version'] = 1
        except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        # Get distro information
        if wsl_info['is_wsl']:
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            wsl_info['distro'] = line.split('=')[1].strip().strip('"')
                            break
            except Exception as e:
                logger.debug(f"Suppressed error: {e}")

        return wsl_info


class TestExecutor:
    """Executes tests in different environments."""

    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.detector = EnvironmentDetector()
        self.results_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=4)

    def execute_test(self, test_command: str, environment: TestEnvironment,
                    timeout: Optional[int] = None) -> TestResult:
        """
        Execute a test command in the specified environment.

        Args:
            test_command: Command to execute
            environment: Target environment configuration
            timeout: Execution timeout in seconds

        Returns:
            TestResult object
        """
        start_time = time.time()
        timeout = timeout or environment.timeout_seconds

        result = TestResult(
            environment_name=environment.name,
            test_name=test_command,
            passed=False,
            execution_time=0,
            output=""
        )

        try:
            # Setup environment if needed
            for setup_cmd in environment.setup_commands:
                subprocess.run(setup_cmd, shell=False, check=True, capture_output=True, timeout=30)  # noqa: S603

            # Execute the test
            process = subprocess.run(  # noqa: S603
                test_command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            result.output = process.stdout
            result.error = process.stderr if process.stderr else None
            result.passed = (process.returncode == 0)

            # Collect metrics
            result.metrics = {
                'return_code': process.returncode,
                'stdout_lines': len(process.stdout.splitlines()),
                'stderr_lines': len(process.stderr.splitlines()) if process.stderr else 0
            }

        except subprocess.TimeoutExpired as e:
            result.error = f"Test timeout after {timeout} seconds"
            result.output = e.stdout.decode() if e.stdout else ""

        except subprocess.CalledProcessError as e:
            result.error = f"Setup command failed: {e}"
            result.output = e.stdout.decode() if e.stdout else ""

        except Exception as e:
            result.error = f"Unexpected error: {str(e)}\n{traceback.format_exc()}"

        finally:
            # Teardown environment
            for teardown_cmd in environment.teardown_commands:
                try:
                    subprocess.run(teardown_cmd, shell=False, capture_output=True, timeout=30)  # noqa: S603
                except Exception as e:
                    logger.debug(f"Suppressed error: {e}")

            result.execution_time = time.time() - start_time

        return result

    def validate_environment_compatibility(self, environment: TestEnvironment) -> Dict[str, Any]:
        """
        Check if current system can run tests for the target environment.

        Args:
            environment: Target environment to validate

        Returns:
            Compatibility check results
        """
        compatibility = {
            'compatible': True,
            'warnings': [],
            'errors': [],
            'current_environment': {}
        }

        # Get current environment info
        hw_validator = HardwareValidator()
        current_hw = hw_validator.collect_hardware_info()

        compatibility['current_environment'] = {
            'os': platform.system(),
            'architecture': platform.machine(),
            'is_vm': current_hw.is_virtualized,
            'container': self.detector.detect_container(),
            'cloud': self.detector.detect_cloud_provider(),
            'wsl': self.detector.detect_wsl()
        }

        # Check OS compatibility
        if environment.platform_os != 'any':
            current_os = platform.system().lower()
            expected_os = environment.platform_os.lower()

            if expected_os == 'windows' and current_os != 'windows':
                compatibility['errors'].append(
                    f"Environment requires Windows but running on {current_os}"
                )
                compatibility['compatible'] = False
            elif expected_os == 'linux' and current_os not in ['linux', 'darwin']:
                compatibility['errors'].append(
                    f"Environment requires Linux but running on {current_os}"
                )
                compatibility['compatible'] = False

        # Check architecture compatibility
        if environment.architecture != 'any':
            current_arch = platform.machine().lower()
            expected_arch = environment.architecture.lower()

            if expected_arch not in current_arch and current_arch not in expected_arch:
                compatibility['warnings'].append(
                    f"Architecture mismatch: expected {expected_arch}, got {current_arch}"
                )

        # Check virtualization requirements
        if not environment.requirements.get('virtualized') and current_hw.is_virtualized:
            compatibility['warnings'].append("Environment requires bare metal but running in VM")

        if environment.requirements.get('virtualized') and not current_hw.is_virtualized:
            compatibility['warnings'].append("Environment requires VM but running on bare metal")

        # Check container requirements
        container_info = compatibility['current_environment']['container']
        if environment.environment_type == 'container' and not container_info['is_container']:
            compatibility['errors'].append(
                "Environment requires container but not running in container"
            )
            compatibility['compatible'] = False

        # Check cloud requirements
        cloud_info = compatibility['current_environment']['cloud']
        if environment.environment_type == 'cloud' and not cloud_info['is_cloud']:
            compatibility['warnings'].append("Environment requires cloud but not running in cloud")

        return compatibility


class MultiEnvironmentTester:
    """Orchestrates testing across multiple environments."""

    def __init__(self, validation_path: str):
        self.validation_path = Path(validation_path)
        self.executor = TestExecutor(validation_path)
        self.environments = self._load_environment_matrix()
        self.test_suite = self._load_test_suite()
        self.results = []

    def _load_environment_matrix(self) -> List[TestEnvironment]:
        """
        Load the environment testing matrix.

        Returns:
            List of test environments
        """
        environments = []

        # Bare Metal Windows
        environments.append(TestEnvironment(
            name="Bare Metal Windows x64",
            environment_type="bare_metal",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'virtualized': False,
                'min_ram_gb': 8,
                'min_cores': 4
            },
            validation_criteria={
                'no_vm_artifacts': True,
                'no_hypervisor': True,
                'hardware_acceleration': True
            },
            tags=['critical', 'windows', 'bare_metal']
        ))

        # VMware Workstation
        environments.append(TestEnvironment(
            name="VMware Workstation Pro",
            environment_type="vm",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'virtualized': True,
                'hypervisor': 'vmware',
                'vmtools_installed': True
            },
            validation_criteria={
                'vm_detection': True,
                'vmware_artifacts': True
            },
            setup_commands=[
                'net start VMTools',
                'C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe -v'
            ],
            tags=['high', 'windows', 'vmware']
        ))

        # VirtualBox
        environments.append(TestEnvironment(
            name="Oracle VirtualBox",
            environment_type="vm",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'virtualized': True,
                'hypervisor': 'virtualbox',
                'guest_additions': True
            },
            validation_criteria={
                'vm_detection': True,
                'vbox_artifacts': True
            },
            setup_commands=[
                'VBoxService --version'
            ],
            tags=['high', 'windows', 'virtualbox']
        ))

        # Hyper-V
        environments.append(TestEnvironment(
            name="Microsoft Hyper-V Gen2",
            environment_type="vm",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'virtualized': True,
                'hypervisor': 'hyperv',
                'generation': 2,
                'secure_boot': True
            },
            validation_criteria={
                'vm_detection': True,
                'hyperv_artifacts': True,
                'uefi_boot': True
            },
            tags=['medium', 'windows', 'hyperv']
        ))

        # Docker Windows Container
        environments.append(TestEnvironment(
            name="Docker Windows Container",
            environment_type="container",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'containerized': True,
                'runtime': 'docker',
                'isolation': 'process'
            },
            validation_criteria={
                'container_detection': True,
                'docker_artifacts': True
            },
            setup_commands=[
                'docker version'
            ],
            tags=['low', 'windows', 'docker']
        ))

        # WSL2
        environments.append(TestEnvironment(
            name="Windows Subsystem for Linux 2",
            environment_type="wsl",
            platform_os="linux",
            architecture="x86_64",
            requirements={
                'wsl': True,
                'version': 2,
                'distro': 'ubuntu'
            },
            validation_criteria={
                'wsl_detection': True,
                'kernel_microsoft': True
            },
            setup_commands=[
                'wsl --status'
            ],
            tags=['medium', 'linux', 'wsl']
        ))

        # AWS EC2
        environments.append(TestEnvironment(
            name="AWS EC2 Windows",
            environment_type="cloud",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'cloud': True,
                'provider': 'aws',
                'instance_type': 't3.medium'
            },
            validation_criteria={
                'cloud_detection': True,
                'aws_metadata': True
            },
            tags=['medium', 'windows', 'cloud', 'aws']
        ))

        # Azure VM
        environments.append(TestEnvironment(
            name="Azure Windows VM",
            environment_type="cloud",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'cloud': True,
                'provider': 'azure',
                'size': 'Standard_B2s'
            },
            validation_criteria={
                'cloud_detection': True,
                'azure_metadata': True
            },
            tags=['medium', 'windows', 'cloud', 'azure']
        ))

        # Anti-Analysis Environment
        environments.append(TestEnvironment(
            name="Hardened Anti-Analysis",
            environment_type="bare_metal",
            platform_os="windows",
            architecture="x86_64",
            requirements={
                'anti_debug': True,
                'anti_vm': True,
                'packer_detection': True,
                'obfuscation': True
            },
            validation_criteria={
                'bypass_anti_debug': True,
                'bypass_anti_vm': True,
                'unpack_success': True
            },
            timeout_seconds=600,
            tags=['critical', 'windows', 'anti_analysis']
        ))

        return environments

    def _load_test_suite(self) -> List[Dict[str, Any]]:
        """
        Load the test suite to run in each environment.

        Returns:
            List of test configurations
        """
        tests = [
            {
                'name': 'Hardware Detection',
                'command': (
                    'C:\\Intellicrack\\.pixi\\envs\\default\\python.exe -c "from tests.validation_system.'
                    'environment_validator import HardwareValidator; v = HardwareValidator(); '
                    'print(v.collect_hardware_info())"'
                ),
                'expected_output_contains': ['CPU Model', 'RAM'],
                'tags': ['basic', 'hardware']
            },
            {
                'name': 'VM Detection',
                'command': (
                    'C:\\Intellicrack\\.pixi\\envs\\default\\python.exe -c "from tests.validation_system.'
                    'environment_validator import HardwareValidator; v = HardwareValidator(); '
                    'print(f\'Is VM: {v.is_virtual_machine()}\')"'
                ),
                'expected_output_contains': ['Is VM:'],
                'tags': ['basic', 'detection']
            },
            {
                'name': 'Protection Analysis',
                'command': (
                    'C:\\Intellicrack\\.pixi\\envs\\default\\python.exe -m intellicrack '
                    '--analyze-protection notepad.exe'
                ),
                'expected_output_contains': ['Analysis complete'],
                'tags': ['core', 'protection']
            },
            {
                'name': 'Binary Analysis',
                'command': (
                    'C:\\Intellicrack\\.pixi\\envs\\default\\python.exe -c "from intellicrack.core.'
                    'binary_analyzer import BinaryAnalyzer; analyzer = BinaryAnalyzer(); '
                    'print(\'BinaryAnalyzer initialized\')"'
                ),
                'expected_output_contains': ['BinaryAnalyzer initialized'],
                'tags': ['core', 'analysis']
            },
            {
                'name': 'Network License Detection',
                'command': (
                    'C:\\Intellicrack\\.pixi\\envs\\default\\python.exe -c "from intellicrack.core.'
                    'network.license_server import NetworkLicenseDetector; '
                    'detector = NetworkLicenseDetector(); print(\'NetworkLicenseDetector ready\')"'
                ),
                'expected_output_contains': ['NetworkLicenseDetector ready'],
                'tags': ['network', 'license']
            }
        ]

        return tests

    def run_compatibility_check(self) -> Dict[str, Any]:
        """
        Check compatibility with all environments.

        Returns:
            Compatibility report
        """
        report = {
            'timestamp': time.time(),
            'current_environment': {},
            'compatibility_matrix': []
        }

        for env in self.environments:
            compat = self.executor.validate_environment_compatibility(env)
            report['compatibility_matrix'].append({
                'environment': env.name,
                'compatible': compat['compatible'],
                'warnings': compat['warnings'],
                'errors': compat['errors']
            })

        # Store current environment info from first check
        if report['compatibility_matrix']:
            report['current_environment'] = self.executor.validate_environment_compatibility(
                self.environments[0]
            )['current_environment']

        return report

    def run_test_suite(self, environment_filter: Optional[List[str]] = None,
                      tag_filter: Optional[List[str]] = None) -> List[TestResult]:
        """
        Run the test suite across selected environments.

        Args:
            environment_filter: List of environment names to test (None = all)
            tag_filter: List of tags to filter environments

        Returns:
            List of test results
        """
        results = []

        # Filter environments
        environments_to_test = self.environments
        if environment_filter:
            environments_to_test = [e for e in environments_to_test if e.name in environment_filter]
        if tag_filter:
            environments_to_test = [e for e in environments_to_test
                                  if any(tag in e.tags for tag in tag_filter)]

        print(f"[*] Testing across {len(environments_to_test)} environments")

        for env in environments_to_test:
            print(f"\n[*] Testing in environment: {env.name}")

            # Check compatibility
            compat = self.executor.validate_environment_compatibility(env)
            if not compat['compatible']:
                print(f"[!] Environment not compatible: {compat['errors']}")
                continue

            if compat['warnings']:
                print(f"[!] Warnings: {compat['warnings']}")

            # Run each test
            for test in self.test_suite:
                print(f"  [*] Running test: {test['name']}")

                result = self.executor.execute_test(
                    test['command'],
                    env,
                    timeout=60
                )

                # Check expected output
                if test.get('expected_output_contains'):
                    for expected in test['expected_output_contains']:
                        if expected not in result.output:
                            result.passed = False
                            result.error = f"Expected output not found: {expected}"

                results.append(result)

                if result.passed:
                    print(f"    [+] PASSED in {result.execution_time:.2f}s")
                else:
                    print(f"    [-] FAILED: {result.error}")

        self.results = results
        return results

    def generate_report(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate comprehensive testing report.

        Args:
            output_path: Optional path to save report

        Returns:
            Testing report dictionary
        """
        report = {
            'timestamp': time.time(),
            'total_tests': len(self.results),
            'passed': sum(1 for r in self.results if r.passed),
            'failed': sum(1 for r in self.results if not r.passed),
            'environments_tested': list(set(r.environment_name for r in self.results)),
            'compatibility_check': self.run_compatibility_check(),
            'results_by_environment': {},
            'results_by_test': {},
            'failures': []
        }

        # Group results by environment
        for result in self.results:
            if result.environment_name not in report['results_by_environment']:
                report['results_by_environment'][result.environment_name] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'tests': []
                }

            env_results = report['results_by_environment'][result.environment_name]
            env_results['total'] += 1
            if result.passed:
                env_results['passed'] += 1
            else:
                env_results['failed'] += 1
                report['failures'].append({
                    'environment': result.environment_name,
                    'test': result.test_name,
                    'error': result.error
                })

            env_results['tests'].append({
                'name': result.test_name,
                'passed': result.passed,
                'execution_time': result.execution_time,
                'error': result.error
            })

        # Group results by test
        for result in self.results:
            if result.test_name not in report['results_by_test']:
                report['results_by_test'][result.test_name] = {
                    'total': 0,
                    'passed': 0,
                    'failed': 0,
                    'environments': []
                }

            test_results = report['results_by_test'][result.test_name]
            test_results['total'] += 1
            if result.passed:
                test_results['passed'] += 1
            else:
                test_results['failed'] += 1

            test_results['environments'].append({
                'name': result.environment_name,
                'passed': result.passed,
                'execution_time': result.execution_time
            })

        # Calculate success rate
        report['success_rate'] = (
            (report['passed'] / report['total_tests'] * 100)
            if report['total_tests'] > 0 else 0
        )

        # Save report if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            print(f"\n[+] Report saved to: {output_file}")

        return report


def run_multi_environment_testing():
    """Run the multi-environment testing matrix."""
    print("=== Multi-Environment Testing Matrix ===")
    print("[*] Initializing multi-environment tester...")

    tester = MultiEnvironmentTester(r"C:\Intellicrack\tests\validation_system")

    # Run compatibility check first
    print("\n[*] Running compatibility check...")
    compat_report = tester.run_compatibility_check()

    print("\n[*] Current environment:")
    current = compat_report['current_environment']
    print(f"  OS: {current['os']}")
    print(f"  Architecture: {current['architecture']}")
    print(f"  Is VM: {current['is_vm']}")
    print(f"  Container: {current['container']['is_container']}")
    print(f"  Cloud: {current['cloud']['is_cloud']}")
    print(f"  WSL: {current['wsl']['is_wsl']}")

    print("\n[*] Compatibility with test environments:")
    for compat in compat_report['compatibility_matrix']:
        status = "✓" if compat['compatible'] else "✗"
        print(f"  {status} {compat['environment']}")
        if compat['errors']:
            for error in compat['errors']:
                print(f"    ERROR: {error}")
        if compat['warnings']:
            for warning in compat['warnings']:
                print(f"    WARNING: {warning}")

    # Run tests only in compatible environments
    print("\n[*] Starting test suite execution...")
    compatible_envs = [
        c['environment'] for c in compat_report['compatibility_matrix'] if c['compatible']
    ]

    if compatible_envs:
        tester.run_test_suite(environment_filter=compatible_envs[:3])  # Test first 3 compatible

        # Generate report
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_path = (
            f"C:\\Intellicrack\\tests\\validation_system\\reports\\"
            f"multi_env_test_{timestamp}.json"
        )
        report = tester.generate_report(report_path)

        # Print summary
        print("\n" + "="*50)
        print("TESTING SUMMARY")
        print("="*50)
        print(f"Total Tests Run: {report['total_tests']}")
        print(f"Passed: {report['passed']}")
        print(f"Failed: {report['failed']}")
        print(f"Success Rate: {report['success_rate']:.1f}%")
        print(f"Environments Tested: {len(report['environments_tested'])}")

        if report['failures']:
            print("\n[!] Failures:")
            for failure in report['failures'][:5]:  # Show first 5 failures
                print(f"  - {failure['environment']}: {failure['test']}")
                print(f"    Error: {failure['error']}")
    else:
        print("[!] No compatible environments found for testing")

    print("\n[+] Multi-environment testing complete!")


if __name__ == "__main__":
    run_multi_environment_testing()
