"""
Phase 6.6: Reproducibility Requirements Checker

This module implements comprehensive validation of reproducibility requirements,
ensuring validation results can be independently verified and reproduced.
"""

import hashlib
import logging
import json
import subprocess
import time
import shutil
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
from enum import Enum
import requests
import yaml
import tempfile
import zipfile

class ReproducibilityResult(Enum):
    """Reproducibility validation result."""
    REPRODUCIBLE = "REPRODUCIBLE"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    PARTIALLY_REPRODUCIBLE = "PARTIALLY_REPRODUCIBLE"
    INVALID = "INVALID"

class ReproducibilityMethod(Enum):
    """Methods for reproduction testing."""
    VAGRANT = "vagrant"
    NATIVE = "native"
    VIRTUAL_MACHINE = "virtual_machine"

@dataclass
class ReproductionPackage:
    """Structure for reproduction package."""
    package_id: str
    creation_timestamp: str
    method: ReproducibilityMethod
    environment_spec: Dict[str, Any]
    dependencies: List[str]
    test_data: Dict[str, Any]
    expected_results: Dict[str, Any]
    verification_checksums: Dict[str, str]

@dataclass
class ReproductionResult:
    """Results from reproduction attempt."""
    success: bool
    method_used: ReproducibilityMethod
    execution_time: float
    results_match: bool
    success_rate_difference: float
    evidence_artifacts: List[Path]
    error_log: Optional[str] = None

class ReproducibilityRequirementsChecker:
    """
    Implements Phase 6.6 requirements for reproducibility validation.

    Requirements:
    - Independent party achieves same results ± 5% success rate
    - All evidence artifacts can be verified by third party
    - Test can be reproduced from Docker/VM image without assistance
    - FAIL conditions: Cannot reproduce = INVALID, Evidence unverifiable = INVALID
    """

    def __init__(self, output_path: Path, packages_path: Path):
        """Initialize reproducibility requirements checker."""
        self.output_path = Path(output_path)
        self.packages_path = Path(packages_path)
        self.logger = logging.getLogger(__name__)

        # Create directories
        self.output_path.mkdir(parents=True, exist_ok=True)
        self.packages_path.mkdir(parents=True, exist_ok=True)

        # Configuration
        self.config = {
            "success_rate_tolerance": 0.05,  # ±5%
            "docker_timeout": 3600,  # 1 hour
            "max_retry_attempts": 3,
            "required_evidence_types": [
                "memory_dumps", "network_capture", "api_trace",
                "screen_recording", "file_system_changes"
            ]
        }


    def validate_reproducibility(self, original_results: Dict[str, Any],
                                reproduction_package: ReproductionPackage,
                                methods_to_test: List[ReproducibilityMethod] = None) -> Tuple[ReproducibilityResult, Dict[str, Any]]:
        """
        Validate reproducibility requirements against Phase 6.6 criteria.

        Args:
            original_results: Original validation results to reproduce
            reproduction_package: Package containing reproduction instructions
            methods_to_test: Methods to test (default: all available)

        Returns:
            Tuple of (ReproducibilityResult, detailed_report)
        """
        validation_report = {
            "timestamp": self._get_timestamp(),
            "original_results": original_results,
            "package_info": asdict(reproduction_package),
            "reproduction_attempts": [],
            "overall_result": ReproducibilityResult.NOT_REPRODUCIBLE,
            "reproducibility_score": 0.0,
            "evidence_verification": {}
        }

        try:
            if methods_to_test is None:
                methods_to_test = [ReproducibilityMethod.NATIVE, ReproducibilityMethod.VAGRANT]

            reproduction_results = []
            successful_reproductions = 0

            # Test each reproduction method
            for method in methods_to_test:
                if self._is_method_available(method):
                    self.logger.info(f"Testing reproducibility using {method.value}")

                    result = self._attempt_reproduction(
                        method, reproduction_package, original_results
                    )
                    reproduction_results.append(result)
                    validation_report["reproduction_attempts"].append(asdict(result))

                    if result.success and result.results_match:
                        successful_reproductions += 1
                else:
                    self.logger.warning(f"Method {method.value} not available")

            # 6.6.1: Validate success rate tolerance
            success_rate_valid = self._validate_success_rate_tolerance(
                reproduction_results, original_results, validation_report
            )

            # 6.6.2: Validate evidence artifact verification
            evidence_valid = self._validate_evidence_verification(
                reproduction_results, validation_report
            )

            # 6.6.3: Validate independent reproduction capability
            independence_valid = self._validate_independent_reproduction(
                reproduction_results, validation_report
            )

            # Determine overall result
            if len(methods_to_test) > 0:
                success_percentage = successful_reproductions / len(methods_to_test)
                validation_report["reproducibility_score"] = success_percentage

                if success_percentage >= 1.0 and success_rate_valid and evidence_valid and independence_valid:
                    validation_report["overall_result"] = ReproducibilityResult.REPRODUCIBLE
                elif success_percentage >= 0.5:
                    validation_report["overall_result"] = ReproducibilityResult.PARTIALLY_REPRODUCIBLE
                else:
                    validation_report["overall_result"] = ReproducibilityResult.NOT_REPRODUCIBLE

        except Exception as e:
            self.logger.error(f"Reproducibility validation failed: {e}")
            validation_report["overall_result"] = ReproducibilityResult.INVALID
            validation_report["error"] = str(e)

        return validation_report["overall_result"], validation_report

    def _attempt_reproduction(self, method: ReproducibilityMethod,
                            package: ReproductionPackage,
                            original_results: Dict[str, Any]) -> ReproductionResult:
        """Attempt reproduction using specified method."""
        start_time = time.time()

        try:
            if method == ReproducibilityMethod.VAGRANT:
                return self._reproduce_with_vagrant(package, original_results)
            elif method == ReproducibilityMethod.NATIVE:
                return self._reproduce_natively(package, original_results)
            else:
                return ReproductionResult(
                    success=False,
                    method_used=method,
                    execution_time=time.time() - start_time,
                    results_match=False,
                    success_rate_difference=1.0,
                    evidence_artifacts=[],
                    error_log=f"Reproduction method {method.value} not implemented"
                )

        except Exception as e:
            return ReproductionResult(
                success=False,
                method_used=method,
                execution_time=time.time() - start_time,
                results_match=False,
                success_rate_difference=1.0,
                evidence_artifacts=[],
                error_log=str(e)
            )

    def _reproduce_with_vagrant(self, package: ReproductionPackage,
                              original_results: Dict[str, Any]) -> ReproductionResult:
        """Reproduce validation using Vagrant VM."""
        start_time = time.time()

        try:
            # Create Vagrantfile
            vagrantfile_content = self._generate_vagrantfile(package)
            vagrant_dir = self.packages_path / f"vagrant_{package.package_id}"
            vagrant_dir.mkdir(exist_ok=True)

            vagrantfile_path = vagrant_dir / "Vagrantfile"
            with open(vagrantfile_path, 'w') as f:
                f.write(vagrantfile_content)

            # Prepare provisioning script
            provision_script = self._generate_provision_script(package)
            provision_path = vagrant_dir / "provision.sh"
            with open(provision_path, 'w') as f:
                f.write(provision_script)

            # Start Vagrant VM
            self.logger.info("Starting Vagrant VM...")
            subprocess.run(
                ["vagrant", "up"],
                cwd=vagrant_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config["docker_timeout"]
            )

            # Run validation in VM
            result = subprocess.run(
                ["vagrant", "ssh", "-c", "sudo /vagrant/provision.sh"],
                cwd=vagrant_dir,
                capture_output=True,
                text=True,
                timeout=self.config["docker_timeout"]
            )

            # Extract and compare results
            vm_results = self._extract_vagrant_results(vagrant_dir)
            results_match, success_rate_diff = self._compare_results(vm_results, original_results)

            # Collect evidence
            evidence_artifacts = self._collect_evidence_from_vagrant(vagrant_dir)

            # Cleanup
            subprocess.run(["vagrant", "destroy", "-f"], cwd=vagrant_dir, capture_output=True)
            shutil.rmtree(vagrant_dir, ignore_errors=True)

            return ReproductionResult(
                success=result.returncode == 0,
                method_used=ReproducibilityMethod.VAGRANT,
                execution_time=time.time() - start_time,
                results_match=results_match,
                success_rate_difference=success_rate_diff,
                evidence_artifacts=evidence_artifacts,
                error_log=result.stderr if result.returncode != 0 else None
            )

        except Exception as e:
            return ReproductionResult(
                success=False,
                method_used=ReproducibilityMethod.VAGRANT,
                execution_time=time.time() - start_time,
                results_match=False,
                success_rate_difference=1.0,
                evidence_artifacts=[],
                error_log=str(e)
            )

    def _reproduce_natively(self, package: ReproductionPackage,
                          original_results: Dict[str, Any]) -> ReproductionResult:
        """Reproduce validation natively on current system."""
        start_time = time.time()

        try:
            # Create isolated environment
            temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_repro_"))

            # Extract reproduction package
            self._extract_reproduction_package(package, temp_dir)

            # Install dependencies
            self._install_dependencies(package.dependencies, temp_dir)

            # Set environment variables
            env = dict(os.environ)
            env.update(package.environment_spec.get('environment_variables', {}))

            # Run validation
            validation_script = temp_dir / "run_validation.py"
            result = subprocess.run(
                ["python", str(validation_script)],
                cwd=temp_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.config["docker_timeout"]
            )

            # Extract and compare results
            native_results = self._extract_native_results(temp_dir)
            results_match, success_rate_diff = self._compare_results(native_results, original_results)

            # Collect evidence
            evidence_artifacts = self._collect_evidence_from_native(temp_dir)

            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

            return ReproductionResult(
                success=result.returncode == 0,
                method_used=ReproducibilityMethod.NATIVE,
                execution_time=time.time() - start_time,
                results_match=results_match,
                success_rate_difference=success_rate_diff,
                evidence_artifacts=evidence_artifacts,
                error_log=result.stderr if result.returncode != 0 else None
            )

        except Exception as e:
            return ReproductionResult(
                success=False,
                method_used=ReproducibilityMethod.NATIVE,
                execution_time=time.time() - start_time,
                results_match=False,
                success_rate_difference=1.0,
                evidence_artifacts=[],
                error_log=str(e)
            )

    def _validate_success_rate_tolerance(self, reproduction_results: List[ReproductionResult],
                                       original_results: Dict[str, Any],
                                       report: Dict[str, Any]) -> bool:
        """6.6.1: Validate success rate within ±5% tolerance."""
        try:
            original_success_rate = original_results.get("success_rate", 0.0)
            tolerance = self.config["success_rate_tolerance"]

            valid_reproductions = []

            for result in reproduction_results:
                if result.success:
                    within_tolerance = abs(result.success_rate_difference) <= tolerance
                    valid_reproductions.append({
                        "method": result.method_used.value,
                        "within_tolerance": within_tolerance,
                        "success_rate_difference": result.success_rate_difference,
                        "tolerance": tolerance
                    })

            all_within_tolerance = all(r["within_tolerance"] for r in valid_reproductions)

            report["success_rate_validation"] = {
                "pass": all_within_tolerance,
                "original_success_rate": original_success_rate,
                "tolerance": tolerance,
                "reproduction_results": valid_reproductions
            }

            return all_within_tolerance

        except Exception as e:
            report["success_rate_validation"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    def _validate_evidence_verification(self, reproduction_results: List[ReproductionResult],
                                      report: Dict[str, Any]) -> bool:
        """6.6.2: Validate evidence artifacts can be verified."""
        try:
            verification_results = {}
            all_evidence_valid = True

            for result in reproduction_results:
                method_verification = {
                    "artifacts_found": len(result.evidence_artifacts),
                    "verified_artifacts": 0,
                    "verification_details": []
                }

                for artifact_path in result.evidence_artifacts:
                    verification = self._verify_evidence_artifact(artifact_path)
                    method_verification["verification_details"].append(verification)

                    if verification["valid"]:
                        method_verification["verified_artifacts"] += 1
                    else:
                        all_evidence_valid = False

                verification_results[result.method_used.value] = method_verification

            report["evidence_verification"] = {
                "pass": all_evidence_valid,
                "by_method": verification_results
            }

            return all_evidence_valid

        except Exception as e:
            report["evidence_verification"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    def _validate_independent_reproduction(self, reproduction_results: List[ReproductionResult],
                                         report: Dict[str, Any]) -> bool:
        """6.6.3: Validate test can be reproduced without assistance."""
        try:
            independence_results = {}
            all_independent = True

            for result in reproduction_results:
                # Check if reproduction was successful without manual intervention
                independent = (
                    result.success and
                    result.results_match and
                    result.error_log is None
                )

                independence_results[result.method_used.value] = {
                    "independent": independent,
                    "success": result.success,
                    "results_match": result.results_match,
                    "has_errors": result.error_log is not None
                }

                if not independent:
                    all_independent = False

            report["independence_validation"] = {
                "pass": all_independent,
                "by_method": independence_results
            }

            return all_independent

        except Exception as e:
            report["independence_validation"] = {
                "pass": False,
                "error": str(e)
            }
            return False

    # Helper methods for reproduction

    def _is_method_available(self, method: ReproducibilityMethod) -> bool:
        """Check if reproduction method is available."""
        if method == ReproducibilityMethod.VAGRANT:
            return shutil.which("vagrant") is not None
        elif method == ReproducibilityMethod.NATIVE:
            return True
        return False

    def _generate_vagrantfile(self, package: ReproductionPackage) -> str:
        """Generate Vagrantfile for reproduction."""
        box = package.environment_spec.get('vagrant_box', 'ubuntu/focal64')
        memory = package.environment_spec.get('memory', 2048)
        cpus = package.environment_spec.get('cpus', 2)

        vagrantfile = f"""
Vagrant.configure("2") do |config|
  config.vm.box = "{box}"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "{memory}"
    vb.cpus = {cpus}
  end

  config.vm.provision "shell", path: "provision.sh"
end
"""
        return vagrantfile

    def _generate_provision_script(self, package: ReproductionPackage) -> str:
        """Generate provisioning script for Vagrant."""
        script = """#!/bin/bash
set -e

# Update system
apt-get update
apt-get install -y python3 python3-pip wget curl git

# Install dependencies
""" + "\\n".join(f"pip3 install {dep}" for dep in package.dependencies) + """

# Set environment variables
""" + "\\n".join(f"export {k}={v}" for k, v in package.environment_spec.get('environment_variables', {}).items()) + """

# Run validation
cd /vagrant
python3 run_validation.py
"""
        return script

    def _format_env_vars(self, env_vars: Dict[str, str]) -> str:
        """Format environment variables for Dockerfile."""
        if not env_vars:
            return ""

        env_lines = []
        for key, value in env_vars.items():
            env_lines.append(f"ENV {key}={value}")

        return "\\n".join(env_lines)

    def _generate_validation_script(self, package: ReproductionPackage) -> str:
        """Generate validation script for reproduction."""
        script = f"""#!/usr/bin/env python3
import json
import sys
import time
from pathlib import Path

def main():
    print("Starting Intellicrack validation reproduction...")

    # Load test data
    test_data = {json.dumps(package.test_data, indent=2)}

    # Execute actual validation tests
    import subprocess
    passed = 0
    failed = 0
    total_tests = test_data.get("total_tests", 0)

    for test_case in test_data.get("test_cases", []):
        try:
            result = subprocess.run(
                [sys.executable, "-c", test_case.get("code", "")],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1
            print(f"Test failed: {{e}}")

    results = {{
        "timestamp": time.time(),
        "success_rate": passed / total_tests if total_tests > 0 else 0.0,
        "total_tests": total_tests,
        "passed_tests": passed,
        "failed_tests": failed,
        "reproduction_id": "{package.package_id}"
    }}

    # Save results
    output_path = Path("/output/reproduction_results.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print("Validation reproduction completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
        return script

    def _compare_results(self, reproduced_results: Dict[str, Any],
                        original_results: Dict[str, Any]) -> Tuple[bool, float]:
        """Compare reproduced results with original."""
        try:
            original_rate = original_results.get("success_rate", 0.0)
            reproduced_rate = reproduced_results.get("success_rate", 0.0)

            success_rate_diff = abs(original_rate - reproduced_rate)
            tolerance = self.config["success_rate_tolerance"]

            results_match = success_rate_diff <= tolerance

            return results_match, success_rate_diff

        except Exception as e:
            self.logger.error(f"Results comparison failed: {e}")
            return False, 1.0

    def _verify_evidence_artifact(self, artifact_path: Path) -> Dict[str, Any]:
        """Verify individual evidence artifact."""
        try:
            if not artifact_path.exists():
                return {"valid": False, "reason": "Artifact file not found"}

            # Calculate checksum
            checksum = self._calculate_file_hash(artifact_path)

            # Basic format validation
            if artifact_path.suffix in ['.pcap', '.pcapng']:
                valid = self._validate_pcap_file(artifact_path)
            elif artifact_path.suffix in ['.mp4', '.avi']:
                valid = self._validate_video_file(artifact_path)
            else:
                valid = True  # Basic existence check

            return {
                "valid": valid,
                "checksum": checksum,
                "size": artifact_path.stat().st_size,
                "format_valid": valid
            }

        except Exception as e:
            return {"valid": False, "error": str(e)}

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

    def _validate_pcap_file(self, file_path: Path) -> bool:
        """Validate PCAP file format."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            return magic in [b'\\xd4\\xc3\\xb2\\xa1', b'\\xa1\\xb2\\xc3\\xd4', b'\\x0a\\x0d\\x0d\\x0a']
        except Exception:
            return False

    def _validate_video_file(self, file_path: Path) -> bool:
        """Validate video file format."""
        try:
            # Basic validation - check file size and extension
            return file_path.stat().st_size > 1024  # At least 1KB
        except Exception:
            return False

    def _get_timestamp(self) -> str:
        """Get ISO timestamp."""
        return datetime.utcnow().isoformat() + 'Z'

    # Environment-specific extraction methods for Vagrant

    def _extract_vagrant_results(self, vagrant_dir: Path) -> Dict[str, Any]:
        """Extract results from Vagrant VM."""
        import subprocess
        import json

        results = {
            'success_rate': 0.0,
            'reproduction_method': 'vagrant',
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_details': [],
            'vm_info': {},
            'errors': []
        }

        try:
            # Change to vagrant directory for commands
            original_cwd = Path.cwd()
            os.chdir(vagrant_dir)

            try:
                # Check if VM is running
                status_result = subprocess.run(
                    ['vagrant', 'status'],
                    capture_output=True, text=True, timeout=30
                )

                if 'running' not in status_result.stdout.lower():
                    results['errors'].append("Vagrant VM is not running")
                    return results

                # Execute command to get test results from VM
                commands_to_try = [
                    'cat /vagrant/test_results.json',
                    'cat /home/vagrant/test_results.json',
                    'cat /tmp/test_results.json',
                    'find /vagrant -name "test_results.json" -exec cat {} \\;'
                ]

                results_found = False
                for cmd in commands_to_try:
                    try:
                        exec_result = subprocess.run(
                            ['vagrant', 'ssh', '-c', cmd],
                            capture_output=True, text=True, timeout=60
                        )

                        if exec_result.returncode == 0 and exec_result.stdout.strip():
                            # Try to parse JSON results
                            test_data = json.loads(exec_result.stdout.strip())

                            if 'tests' in test_data:
                                tests = test_data['tests']
                                results['total_tests'] = len(tests)
                                results['passed_tests'] = sum(1 for test in tests if test.get('passed', False))
                                results['failed_tests'] = results['total_tests'] - results['passed_tests']
                                results['test_details'] = tests

                                if results['total_tests'] > 0:
                                    results['success_rate'] = results['passed_tests'] / results['total_tests']

                            results_found = True
                            break

                    except (json.JSONDecodeError, subprocess.TimeoutExpired) as e:
                        self.logger.warning(f"Failed to parse results from command '{cmd}': {e}")
                        continue

                if not results_found:
                    # Fall back to log analysis
                    log_commands = [
                        'cat /vagrant/test.log',
                        'cat /var/log/test_output.log',
                        'journalctl --no-pager | grep -i test'
                    ]

                    success_indicators = 0
                    failure_indicators = 0

                    for log_cmd in log_commands:
                        try:
                            log_result = subprocess.run(
                                ['vagrant', 'ssh', '-c', log_cmd],
                                capture_output=True, text=True, timeout=30
                            )

                            if log_result.returncode == 0:
                                log_content = log_result.stdout.lower()

                                # Count success/failure indicators
                                success_patterns = ['passed', 'success', 'completed', 'verified']
                                failure_patterns = ['failed', 'error', 'exception', 'timeout']

                                for pattern in success_patterns:
                                    success_indicators += log_content.count(pattern)
                                for pattern in failure_patterns:
                                    failure_indicators += log_content.count(pattern)

                        except subprocess.TimeoutExpired:
                            continue

                    # Estimate success rate from log analysis
                    total_indicators = success_indicators + failure_indicators
                    if total_indicators > 0:
                        results['success_rate'] = success_indicators / total_indicators
                        results['total_tests'] = total_indicators
                        results['passed_tests'] = success_indicators
                        results['failed_tests'] = failure_indicators
                        self.logger.info(f"Estimated Vagrant results from logs: {results['success_rate']:.2%} success rate")
                    else:
                        results['errors'].append("No test results or log indicators found in VM")

                # Get VM system information
                try:
                    sys_info_result = subprocess.run(
                        ['vagrant', 'ssh', '-c', 'uname -a; lscpu | head -20; free -h; df -h'],
                        capture_output=True, text=True, timeout=30
                    )

                    if sys_info_result.returncode == 0:
                        results['vm_info'] = {
                            'system_info': sys_info_result.stdout,
                            'extraction_time': time.time()
                        }

                except subprocess.TimeoutExpired:
                    self.logger.warning("Timeout getting VM system information")

            finally:
                os.chdir(original_cwd)

        except Exception as e:
            self.logger.error(f"Error extracting Vagrant results: {e}")
            results['errors'].append(f"Vagrant extraction error: {str(e)}")

        return results

    def _collect_evidence_from_vagrant(self, vagrant_dir: Path) -> List[Path]:
        """Collect evidence artifacts from Vagrant VM."""
        import subprocess
        import tempfile

        evidence_files = []

        try:
            # Create evidence directory
            vagrant_evidence_dir = Path(tempfile.mkdtemp(prefix='vagrant_evidence_'))

            # Change to vagrant directory for commands
            original_cwd = Path.cwd()
            os.chdir(vagrant_dir)

            try:
                # Check if VM is running
                status_result = subprocess.run(
                    ['vagrant', 'status'],
                    capture_output=True, text=True, timeout=30
                )

                if 'running' not in status_result.stdout.lower():
                    self.logger.warning("Vagrant VM is not running - cannot collect evidence")
                    return evidence_files

                # Define files/directories to copy from VM
                vm_paths_to_copy = [
                    '/vagrant/test_results.json',
                    '/vagrant/logs/',
                    '/home/vagrant/test_output/',
                    '/tmp/test_*.log',
                    '/var/log/test_output.log'
                ]

                for vm_path in vm_paths_to_copy:
                    try:
                        # Use scp to copy files from VM
                        local_filename = vm_path.replace('/', '_').replace('*', 'wildcard').lstrip('_')
                        local_path = vagrant_evidence_dir / local_filename

                        # First check if path exists in VM
                        check_result = subprocess.run(
                            ['vagrant', 'ssh', '-c', f'test -e {vm_path} && echo "EXISTS"'],
                            capture_output=True, text=True, timeout=30
                        )

                        if 'EXISTS' in check_result.stdout:
                            if vm_path.endswith('/'):
                                # Directory - create tar archive first
                                tar_cmd = f'tar -czf /tmp/{local_filename}.tar.gz -C {vm_path} .'
                                tar_result = subprocess.run(
                                    ['vagrant', 'ssh', '-c', tar_cmd],
                                    capture_output=True, text=True, timeout=60
                                )

                                if tar_result.returncode == 0:
                                    # Copy the tar file
                                    scp_result = subprocess.run(
                                        ['vagrant', 'scp', f':/tmp/{local_filename}.tar.gz', str(local_path.with_suffix('.tar.gz'))],
                                        capture_output=True, text=True, timeout=60
                                    )

                                    if scp_result.returncode == 0:
                                        evidence_files.append(local_path.with_suffix('.tar.gz'))
                            else:
                                # Single file or wildcard
                                if '*' in vm_path:
                                    # Handle wildcard by listing matching files first
                                    list_result = subprocess.run(
                                        ['vagrant', 'ssh', '-c', f'ls -la {vm_path} 2>/dev/null'],
                                        capture_output=True, text=True, timeout=30
                                    )

                                    if list_result.returncode == 0 and list_result.stdout.strip():
                                        # Create archive of matching files
                                        archive_cmd = f'tar -czf /tmp/{local_filename}.tar.gz {vm_path} 2>/dev/null'
                                        tar_result = subprocess.run(
                                            ['vagrant', 'ssh', '-c', archive_cmd],
                                            capture_output=True, text=True, timeout=60
                                        )

                                        if tar_result.returncode == 0:
                                            scp_result = subprocess.run(
                                                ['vagrant', 'scp', f':/tmp/{local_filename}.tar.gz', str(local_path.with_suffix('.tar.gz'))],
                                                capture_output=True, text=True, timeout=60
                                            )

                                            if scp_result.returncode == 0:
                                                evidence_files.append(local_path.with_suffix('.tar.gz'))
                                else:
                                    # Single file
                                    scp_result = subprocess.run(
                                        ['vagrant', 'scp', f':{vm_path}', str(local_path)],
                                        capture_output=True, text=True, timeout=60
                                    )

                                    if scp_result.returncode == 0:
                                        evidence_files.append(local_path)

                    except subprocess.TimeoutExpired:
                        self.logger.warning(f"Timeout copying {vm_path} from Vagrant VM")
                    except Exception as e:
                        self.logger.warning(f"Could not copy {vm_path} from Vagrant VM: {e}")

                # Get VM logs
                try:
                    vm_log_result = subprocess.run(
                        ['vagrant', 'ssh', '-c', 'journalctl --no-pager -n 1000'],
                        capture_output=True, text=True, timeout=30
                    )

                    if vm_log_result.returncode == 0:
                        vm_log_file = vagrant_evidence_dir / 'vagrant_system_log.txt'
                        with open(vm_log_file, 'w') as f:
                            f.write(vm_log_result.stdout)
                        evidence_files.append(vm_log_file)

                except subprocess.TimeoutExpired:
                    self.logger.warning("Timeout getting VM system logs")

                # Create Vagrant info file
                vagrant_info = {
                    'vagrant_dir': str(vagrant_dir),
                    'status_output': status_result.stdout,
                    'collection_time': time.time(),
                    'total_evidence_files': len(evidence_files)
                }

                info_file = vagrant_evidence_dir / 'vagrant_info.json'
                with open(info_file, 'w') as f:
                    json.dump(vagrant_info, f, indent=2)
                evidence_files.append(info_file)

                self.logger.info(f"Collected {len(evidence_files)} evidence files from Vagrant VM")

            finally:
                os.chdir(original_cwd)

        except Exception as e:
            self.logger.error(f"Error collecting evidence from Vagrant VM: {e}")

        return evidence_files

    def _extract_reproduction_package(self, package: ReproductionPackage, temp_dir: Path) -> None:
        """Extract reproduction package to temporary directory."""
        import zipfile
        import tarfile
        import json

        try:
            # Create extraction directory
            extract_dir = temp_dir / "extracted_package"
            extract_dir.mkdir(parents=True, exist_ok=True)

            # Extract based on package type
            if hasattr(package, 'archive_path') and package.archive_path:
                archive_path = Path(package.archive_path)

                if archive_path.suffix.lower() == '.zip':
                    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                        self.logger.info(f"Extracted ZIP package to {extract_dir}")

                elif archive_path.suffix.lower() in ['.tar', '.tar.gz', '.tgz']:
                    with tarfile.open(archive_path, 'r:*') as tar_ref:
                        tar_ref.extractall(extract_dir)
                        self.logger.info(f"Extracted TAR package to {extract_dir}")

                else:
                    raise ValueError(f"Unsupported archive format: {archive_path.suffix}")

            # Extract package metadata
            metadata_file = extract_dir / "package_metadata.json"
            metadata = {
                'package_id': getattr(package, 'package_id', 'unknown'),
                'extraction_time': time.time(),
                'extraction_path': str(extract_dir),
                'original_test_results': getattr(package, 'original_results', {}),
                'dependencies': getattr(package, 'dependencies', []),
                'environment_info': getattr(package, 'environment', {}),
                'reproduction_method': getattr(package, 'method', 'unknown')
            }

            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Validate extraction
            required_files = ['test_data', 'results', 'environment.json']
            missing_files = []
            for req_file in required_files:
                if not (extract_dir / req_file).exists():
                    missing_files.append(req_file)

            if missing_files:
                self.logger.warning(f"Missing required files in reproduction package: {missing_files}")

        except Exception as e:
            self.logger.error(f"Failed to extract reproduction package: {e}")
            raise RuntimeError(f"Package extraction failed: {e}")

    def _install_dependencies(self, dependencies: List[str], temp_dir: Path) -> None:
        """Install dependencies for native reproduction."""
        import subprocess
        import platform

        if not dependencies:
            self.logger.info("No dependencies to install")
            return

        install_log_path = temp_dir / "dependency_install.log"
        failed_dependencies = []

        try:
            with open(install_log_path, 'w') as log_file:
                log_file.write(f"Dependency installation log - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Platform: {platform.system()} {platform.release()}\n")
                log_file.write(f"Dependencies to install: {dependencies}\n\n")

                for dependency in dependencies:
                    try:
                        self.logger.info(f"Installing dependency: {dependency}")
                        log_file.write(f"Installing {dependency}...\n")

                        # Determine installation method based on dependency format
                        if dependency.endswith('.msi'):
                            # Windows MSI installer
                            cmd = ['msiexec', '/i', dependency, '/quiet', '/norestart']
                        elif dependency.endswith('.exe'):
                            # Windows executable installer
                            cmd = [dependency, '/S']  # Silent install
                        elif dependency.startswith('pip:'):
                            # Python package
                            package_name = dependency.replace('pip:', '')
                            cmd = ['pip', 'install', package_name, '--user']
                        elif dependency.startswith('choco:'):
                            # Chocolatey package (Windows)
                            package_name = dependency.replace('choco:', '')
                            cmd = ['choco', 'install', package_name, '-y']
                        elif dependency.startswith('nuget:'):
                            # NuGet package
                            package_name = dependency.replace('nuget:', '')
                            cmd = ['nuget', 'install', package_name]
                        else:
                            # Try to determine from file extension or name
                            dep_path = Path(dependency)
                            if dep_path.exists():
                                if dep_path.suffix == '.zip':
                                    # Extract archive dependency
                                    import zipfile
                                    with zipfile.ZipFile(dep_path, 'r') as zip_ref:
                                        zip_ref.extractall(temp_dir / "dependencies" / dep_path.stem)
                                    log_file.write(f"Extracted archive dependency: {dependency}\n")
                                    continue
                                else:
                                    # Try to execute as installer
                                    cmd = [str(dep_path)]
                            else:
                                # Treat as command-line tool or package name
                                cmd = ['winget', 'install', dependency, '--silent']

                        # Execute installation command
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=300,  # 5 minute timeout
                            cwd=temp_dir
                        )

                        if result.returncode == 0:
                            self.logger.info(f"Successfully installed: {dependency}")
                            log_file.write(f"SUCCESS: {dependency} installed\n")
                            log_file.write(f"Output: {result.stdout}\n\n")
                        else:
                            self.logger.warning(f"Failed to install dependency {dependency}: {result.stderr}")
                            failed_dependencies.append(dependency)
                            log_file.write(f"FAILED: {dependency}\n")
                            log_file.write(f"Error: {result.stderr}\n")
                            log_file.write(f"Return code: {result.returncode}\n\n")

                    except subprocess.TimeoutExpired:
                        self.logger.error(f"Installation timeout for dependency: {dependency}")
                        failed_dependencies.append(dependency)
                        log_file.write(f"TIMEOUT: {dependency}\n\n")

                    except Exception as e:
                        self.logger.error(f"Exception installing dependency {dependency}: {e}")
                        failed_dependencies.append(dependency)
                        log_file.write(f"EXCEPTION: {dependency} - {str(e)}\n\n")

                # Log final results
                log_file.write(f"\nInstallation Summary:\n")
                log_file.write(f"Total dependencies: {len(dependencies)}\n")
                log_file.write(f"Successfully installed: {len(dependencies) - len(failed_dependencies)}\n")
                log_file.write(f"Failed: {len(failed_dependencies)}\n")
                if failed_dependencies:
                    log_file.write(f"Failed dependencies: {failed_dependencies}\n")

        except Exception as e:
            self.logger.error(f"Critical error during dependency installation: {e}")
            raise RuntimeError(f"Dependency installation process failed: {e}")

        if failed_dependencies:
            self.logger.warning(f"Some dependencies failed to install: {failed_dependencies}")
        else:
            self.logger.info("All dependencies installed successfully")

    def _extract_native_results(self, temp_dir: Path) -> Dict[str, Any]:
        """Extract results from native reproduction."""
        import json

        results = {
            'success_rate': 0.0,
            'reproduction_method': 'native',
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_details': [],
            'environment_match': False,
            'performance_metrics': {},
            'errors': []
        }

        try:
            # Look for results files from the native reproduction
            results_files = [
                temp_dir / "test_results.json",
                temp_dir / "extracted_package" / "results" / "test_output.json",
                temp_dir / "reproduction_results.json"
            ]

            results_found = False
            for results_file in results_files:
                if results_file.exists():
                    try:
                        with open(results_file, 'r') as f:
                            test_data = json.load(f)

                        # Extract test results
                        if 'tests' in test_data:
                            tests = test_data['tests']
                            results['total_tests'] = len(tests)
                            results['passed_tests'] = sum(1 for test in tests if test.get('passed', False))
                            results['failed_tests'] = results['total_tests'] - results['passed_tests']
                            results['test_details'] = tests

                        # Calculate success rate
                        if results['total_tests'] > 0:
                            results['success_rate'] = results['passed_tests'] / results['total_tests']

                        # Extract environment information
                        if 'environment' in test_data:
                            env_data = test_data['environment']
                            # Compare with original environment from package metadata
                            metadata_file = temp_dir / "extracted_package" / "package_metadata.json"
                            if metadata_file.exists():
                                with open(metadata_file, 'r') as f:
                                    metadata = json.load(f)
                                    original_env = metadata.get('environment_info', {})

                                # Check environment compatibility
                                env_matches = self._compare_environments(original_env, env_data)
                                results['environment_match'] = env_matches

                        # Extract performance metrics
                        if 'performance' in test_data:
                            results['performance_metrics'] = test_data['performance']

                        results_found = True
                        self.logger.info(f"Extracted results from {results_file}")
                        break

                    except (json.JSONDecodeError, KeyError) as e:
                        self.logger.warning(f"Failed to parse results file {results_file}: {e}")
                        results['errors'].append(f"Parse error in {results_file}: {str(e)}")
                        continue

            if not results_found:
                # Try to analyze log files for basic success indicators
                log_files = list(temp_dir.glob("*.log"))
                if log_files:
                    success_indicators = 0
                    failure_indicators = 0

                    for log_file in log_files:
                        try:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()

                            # Look for success/failure patterns
                            success_patterns = ['success', 'passed', 'completed', 'verified']
                            failure_patterns = ['failed', 'error', 'exception', 'timeout']

                            for pattern in success_patterns:
                                success_indicators += content.count(pattern)
                            for pattern in failure_patterns:
                                failure_indicators += content.count(pattern)

                        except Exception as e:
                            self.logger.warning(f"Failed to analyze log file {log_file}: {e}")

                    # Estimate success rate from log analysis
                    total_indicators = success_indicators + failure_indicators
                    if total_indicators > 0:
                        results['success_rate'] = success_indicators / total_indicators
                        results['total_tests'] = total_indicators
                        results['passed_tests'] = success_indicators
                        results['failed_tests'] = failure_indicators
                        self.logger.info(f"Estimated results from log analysis: {results['success_rate']:.2%} success rate")
                    else:
                        results['errors'].append("No test results or log indicators found")
                        self.logger.warning("No test results could be extracted from native reproduction")
                else:
                    results['errors'].append("No results files or logs found")
                    self.logger.error("No output files found from native reproduction")

        except Exception as e:
            self.logger.error(f"Error extracting native results: {e}")
            results['errors'].append(f"Extraction error: {str(e)}")

        return results

    def _collect_evidence_from_native(self, temp_dir: Path) -> List[Path]:
        """Collect evidence artifacts from native reproduction."""
        evidence_files = []

        try:
            # Define patterns for evidence files
            evidence_patterns = [
                "test_results.*",
                "reproduction_log.*",
                "*.log",
                "evidence/*",
                "output/*",
                "screenshots/*",
                "package_metadata.json",
                "dependency_install.log",
                "environment.json",
                "test_output.*",
                "validation_report.*"
            ]

            # Collect files matching evidence patterns
            for pattern in evidence_patterns:
                matching_files = list(temp_dir.glob(pattern))
                for file_path in matching_files:
                    if file_path.is_file() and file_path not in evidence_files:
                        evidence_files.append(file_path)

            # Also check extracted package directory
            extracted_dir = temp_dir / "extracted_package"
            if extracted_dir.exists():
                for pattern in evidence_patterns:
                    matching_files = list(extracted_dir.rglob(pattern))
                    for file_path in matching_files:
                        if file_path.is_file() and file_path not in evidence_files:
                            evidence_files.append(file_path)

            # Create evidence manifest
            manifest_path = temp_dir / "evidence_manifest.json"
            manifest_data = {
                'collection_time': time.time(),
                'total_files': len(evidence_files),
                'files': [
                    {
                        'path': str(f),
                        'size': f.stat().st_size,
                        'modified': f.stat().st_mtime,
                        'type': f.suffix
                    }
                    for f in evidence_files
                ]
            }

            with open(manifest_path, 'w') as f:
                json.dump(manifest_data, f, indent=2)

            evidence_files.append(manifest_path)

            self.logger.info(f"Collected {len(evidence_files)} evidence files from native reproduction")

        except Exception as e:
            self.logger.error(f"Error collecting evidence from native reproduction: {e}")

        return evidence_files

    def _compare_environments(self, original_env: Dict[str, Any], current_env: Dict[str, Any]) -> bool:
        """Compare two environment configurations for compatibility."""
        try:
            # Key environment factors to compare
            critical_factors = [
                'os_name', 'os_version', 'python_version',
                'architecture', 'cpu_count', 'memory_gb'
            ]

            compatibility_score = 0
            total_factors = len(critical_factors)

            for factor in critical_factors:
                if factor in original_env and factor in current_env:
                    if original_env[factor] == current_env[factor]:
                        compatibility_score += 1
                    elif factor in ['memory_gb', 'cpu_count']:
                        # For numeric factors, allow some tolerance
                        orig_val = float(original_env[factor])
                        curr_val = float(current_env[factor])
                        if abs(orig_val - curr_val) / orig_val <= 0.1:  # 10% tolerance
                            compatibility_score += 0.8

            compatibility_ratio = compatibility_score / total_factors
            return compatibility_ratio >= 0.8  # 80% compatibility threshold

        except Exception as e:
            self.logger.warning(f"Error comparing environments: {e}")
            return False


def main():
    """Example usage of ReproducibilityRequirementsChecker."""
    # Create example reproduction package
    package = ReproductionPackage(
        package_id="test-repro-001",
        creation_timestamp=datetime.utcnow().isoformat() + 'Z',
        method=ReproducibilityMethod.NATIVE,
        environment_spec={
            "base_image": "ubuntu:20.04",
            "environment_variables": {"PYTHONPATH": "/app"}
        },
        dependencies=["numpy", "requests"],
        test_data={"total_tests": 10, "passed_tests": 9},
        expected_results={"success_rate": 0.95},
        verification_checksums={}
    )

    # Initialize checker
    from intellicrack.utils.path_resolver import get_project_root
    checker = ReproducibilityRequirementsChecker(
        output_path=get_project_root() / "tests/validation_system/phase6/reproducibility",
        packages_path=get_project_root() / "tests/validation_system/phase6/packages"
    )

    # Example original results
    original_results = {
        "success_rate": 0.95,
        "total_tests": 10,
        "passed_tests": 9
    }

    # Test reproducibility
    result, report = checker.validate_reproducibility(
        original_results=original_results,
        reproduction_package=package,
        methods_to_test=[ReproducibilityMethod.NATIVE]
    )

    print(f"Reproducibility Result: {result.value}")
    print(f"Reproducibility Score: {report['reproducibility_score']:.2f}")


if __name__ == "__main__":
    main()
