"""Plugin CI/CD system for automated plugin testing and deployment."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any

import yaml

from intellicrack.utils.logger import logger

"""
CI/CD Integration for Intellicrack Plugin Development.

Copyright (C) 2025 Zachary Flint

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


class CICDPipeline:
    """CI/CD pipeline for Intellicrack plugins.

    Manages automated testing, quality checks, security scanning, building,
    and deployment of Intellicrack plugins through a complete pipeline.
    """

    def __init__(self, plugin_path: str) -> None:
        """Initialize CI/CD pipeline with plugin path, configuration, and results tracking.

        Args:
            plugin_path: Path to the plugin file (.py or .js).
        """
        self.plugin_path: str = plugin_path
        self.plugin_dir: str = os.path.dirname(plugin_path)
        self.plugin_name: str = os.path.basename(plugin_path).replace(".py", "").replace(".js", "")
        self.pipeline_config: dict[str, Any] = self._load_or_create_config()
        self.results: dict[str, Any] = {
            "stages": {},
            "overall_status": "pending",
            "timestamp": datetime.now().isoformat(),
        }

    def _load_or_create_config(self) -> dict[str, Any]:
        """Load or create pipeline configuration.

        Loads pipeline configuration from .intellicrack-ci.yml if it exists,
        otherwise creates a default configuration file.

        Returns:
            Pipeline configuration dictionary with stages and settings.
        """
        config_path: str = os.path.join(self.plugin_dir, ".intellicrack-ci.yml")

        if os.path.exists(config_path):
            with open(config_path) as f:
                loaded_config: Any = yaml.safe_load(f)
                return dict(loaded_config) if isinstance(loaded_config, dict) else {}
        else:
            default_config: dict[str, Any] = {
                "version": "1.0",
                "stages": ["validate", "test", "quality", "security", "build", "deploy"],
                "validate": {"enabled": True, "checks": ["syntax", "structure", "imports"]},
                "test": {
                    "enabled": True,
                    "framework": "pytest",
                    "coverage_threshold": 80,
                    "timeout": 300,
                },
                "quality": {
                    "enabled": True,
                    "linters": ["pylint", "flake8"],
                    "max_complexity": 10,
                    "max_line_length": 120,
                },
                "security": {"enabled": True, "scanners": ["bandit"], "check_dependencies": True},
                "build": {"enabled": True, "optimize": True, "minify": False},
                "deploy": {"enabled": True, "target": "local", "backup_previous": True},
            }

            with open(config_path, "w") as f:
                yaml.dump(default_config, f, default_flow_style=False)

            return default_config

    def run_pipeline(self) -> dict[str, Any]:
        """Run the complete CI/CD pipeline.

        Executes all configured pipeline stages in sequence (validate, test,
        quality, security, build, deploy). Stops on first stage failure.

        Returns:
            Dictionary containing stage results, overall status, and timestamp.
        """
        print(f" Starting CI/CD pipeline for {self.plugin_name}")

        stages: Any = self.pipeline_config.get("stages", [])
        if not isinstance(stages, list):
            stages = []

        for stage in stages:
            if not isinstance(stage, str):
                continue

            stage_config: Any = self.pipeline_config.get(stage, {})
            if isinstance(stage_config, dict) and stage_config.get("enabled", True):
                print(f"\n Running stage: {stage}")

                stage_result: dict[str, Any] = getattr(self, f"run_{stage}_stage")()
                stages_dict: dict[str, Any] = self.results["stages"]
                stages_dict[stage] = stage_result

                if not stage_result["success"]:
                    print(f"ERROR Stage '{stage}' failed!")
                    self.results["overall_status"] = "failed"
                    break
                else:
                    print(f"OK Stage '{stage}' passed!")
        else:
            self.results["overall_status"] = "success"

        self._generate_report()

        return self.results

    def run_validate_stage(self) -> dict[str, Any]:
        """Validation stage - check plugin structure.

        Validates plugin syntax, structure, and imports according to
        configuration settings.

        Returns:
            Dictionary with success status, checks, errors, and warnings.
        """
        result: dict[str, Any] = {"success": True, "checks": {}, "errors": [], "warnings": []}

        validate_config: Any = self.pipeline_config.get("validate", {})
        if not isinstance(validate_config, dict):
            validate_config = {}

        checks: Any = validate_config.get("checks", [])
        if not isinstance(checks, list):
            checks = []

        result_checks: dict[str, Any] = result["checks"]
        result_errors: list[Any] = result["errors"]
        result_warnings: list[Any] = result["warnings"]

        if "syntax" in checks:
            syntax_result: dict[str, Any] = self._check_syntax()
            result_checks["syntax"] = syntax_result
            if not syntax_result.get("valid", False):
                result["success"] = False
                result_errors.extend(syntax_result.get("errors", []))

        if "structure" in checks:
            structure_result: dict[str, Any] = self._check_structure()
            result_checks["structure"] = structure_result
            if not structure_result.get("valid", False):
                result["success"] = False
                result_errors.extend(structure_result.get("errors", []))

        if "imports" in checks:
            imports_result: dict[str, Any] = self._check_imports()
            result_checks["imports"] = imports_result
            if imports_result.get("missing"):
                result_warnings.extend(imports_result.get("missing", []))

        return result

    def run_test_stage(self) -> dict[str, Any]:
        """Test stage - run unit tests.

        Runs unit tests using pytest, generates coverage reports, and verifies
        coverage meets configured thresholds.

        Returns:
            Dictionary with test results, coverage percentage, and errors.
        """
        result: dict[str, Any] = {"success": True, "test_results": {}, "coverage": 0, "errors": []}

        test_config: Any = self.pipeline_config.get("test", {})
        if not isinstance(test_config, dict):
            test_config = {"framework": "pytest", "timeout": 300, "coverage_threshold": 80}

        result_errors: list[Any] = result["errors"]

        test_file: str = os.path.join(self.plugin_dir, "tests", f"test_{os.path.basename(self.plugin_path)}")

        if not os.path.exists(test_file):
            from .plugin_test_generator import PluginTestGenerator

            generator: PluginTestGenerator = PluginTestGenerator()
            test_code: str = generator.generate_tests_for_file(self.plugin_path)

            os.makedirs(os.path.dirname(test_file), exist_ok=True)
            with open(test_file, "w") as f:
                f.write(test_code)

        framework: str = test_config.get("framework", "pytest")
        timeout: int = test_config.get("timeout", 300)

        cmd: list[str] = [
            sys.executable,
            "-m",
            framework,
            test_file,
            "-v",
            f"--timeout={timeout}",
            "--tb=short",
        ]

        if framework == "pytest":
            cmd.extend([f"--cov={self.plugin_name}", "--cov-report=json"])

        try:
            process: subprocess.CompletedProcess[str] = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            result["test_results"] = {
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
            }

            if process.returncode != 0:
                result["success"] = False
                result_errors.append("Tests failed")

            coverage_file: str = "coverage.json"
            if os.path.exists(coverage_file):
                with open(coverage_file) as f:
                    coverage_data: Any = json.load(f)
                    if isinstance(coverage_data, dict):
                        totals: Any = coverage_data.get("totals", {})
                        if isinstance(totals, dict):
                            result["coverage"] = totals.get("percent_covered", 0)

                coverage_threshold: int = test_config.get("coverage_threshold", 80)
                coverage_value: Any = result["coverage"]
                if isinstance(coverage_value, (int, float)) and coverage_value < coverage_threshold:
                    result["success"] = False
                    result_errors.append(f"Coverage {coverage_value}% below threshold {coverage_threshold}%")

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in plugin_ci_cd: %s", e)
            result["success"] = False
            result_errors.append(f"Tests timed out after {timeout} seconds")
        except Exception as e:
            logger.error("Exception in plugin_ci_cd: %s", e)
            result["success"] = False
            result_errors.append(f"Test execution error: {str(e)}")

        return result

    def run_quality_stage(self) -> dict[str, Any]:
        """Quality stage - run linters and code quality checks.

        Runs configured linters (pylint, flake8), calculates code complexity,
        and checks line length against thresholds.

        Returns:
            Dictionary with linter results, metrics, and errors.
        """
        result: dict[str, Any] = {"success": True, "linter_results": {}, "metrics": {}, "errors": []}

        quality_config: Any = self.pipeline_config.get("quality", {})
        if not isinstance(quality_config, dict):
            quality_config = {"linters": [], "max_complexity": 10, "max_line_length": 120}

        result_linter_results: dict[str, Any] = result["linter_results"]
        result_metrics: dict[str, Any] = result["metrics"]
        result_errors: list[Any] = result["errors"]

        linters: Any = quality_config.get("linters", [])
        if isinstance(linters, list):
            for linter in linters:
                if not isinstance(linter, str):
                    continue
                linter_result: dict[str, Any] = self._run_linter(linter)
                result_linter_results[linter] = linter_result

                if not linter_result.get("success", True):
                    result["success"] = False
                    issues: Any = linter_result.get("issues", [])
                    if isinstance(issues, list):
                        result_errors.extend(issues)

        complexity: int = self._calculate_complexity()
        result_metrics["complexity"] = complexity

        max_complexity: int = quality_config.get("max_complexity", 10)
        if complexity > max_complexity:
            result["success"] = False
            result_errors.append(f"Code complexity {complexity} exceeds maximum {max_complexity}")

        max_line_length: int = self._check_line_length()
        result_metrics["max_line_length"] = max_line_length

        max_line_length_threshold: int = quality_config.get("max_line_length", 120)
        if max_line_length > max_line_length_threshold:
            result_errors.append(f"Line length {max_line_length} exceeds maximum {max_line_length_threshold}")

        return result

    def run_security_stage(self) -> dict[str, Any]:
        """Security stage - run security scanners.

        Runs security scanners (Bandit) and checks for vulnerable dependencies.
        Fails on high-severity security issues.

        Returns:
            Dictionary with scanner results, vulnerabilities, and errors.
        """
        result: dict[str, Any] = {"success": True, "scanner_results": {}, "vulnerabilities": [], "errors": []}

        security_config: Any = self.pipeline_config.get("security", {})
        if not isinstance(security_config, dict):
            security_config = {"scanners": [], "check_dependencies": True}

        result_scanner_results: dict[str, Any] = result["scanner_results"]
        result_vulnerabilities: list[Any] = result["vulnerabilities"]
        result_errors: list[Any] = result["errors"]

        scanners: Any = security_config.get("scanners", [])
        if isinstance(scanners, list):
            for scanner in scanners:
                if scanner == "bandit":
                    scanner_result: dict[str, Any] = self._run_bandit()
                    result_scanner_results[scanner] = scanner_result

                    issues: Any = scanner_result.get("issues", [])
                    if isinstance(issues, list) and issues:
                        result_vulnerabilities.extend(issues)
                        if any(isinstance(issue, dict) and issue.get("severity") == "HIGH" for issue in issues):
                            result["success"] = False
                            result_errors.append("High severity security issues found")

        check_dependencies: bool = security_config.get("check_dependencies", True)
        if check_dependencies:
            dep_result: dict[str, Any] = self._check_dependencies()
            result["dependencies"] = dep_result

            if vulnerable_packages := dep_result.get("vulnerable_packages"):
                if isinstance(vulnerable_packages, list):
                    result_vulnerabilities.extend(vulnerable_packages)
                result_errors.append("Vulnerable dependencies found")

        return result

    def run_build_stage(self) -> dict[str, Any]:
        """Build stage - optimize and package plugin.

        Creates build directory, copies plugin, optimizes code if configured,
        and generates metadata file with checksums.

        Returns:
            Dictionary with artifact paths and errors.
        """
        result: dict[str, Any] = {"success": True, "artifacts": [], "errors": []}

        build_config: Any = self.pipeline_config.get("build", {})
        if not isinstance(build_config, dict):
            build_config = {"optimize": True, "minify": False}

        result_errors: list[Any] = result["errors"]

        build_dir: str = os.path.join(self.plugin_dir, "build")
        os.makedirs(build_dir, exist_ok=True)

        try:
            dest_path: str = os.path.join(build_dir, os.path.basename(self.plugin_path))
            shutil.copy2(self.plugin_path, dest_path)

            optimize: bool = build_config.get("optimize", True)
            if optimize:
                self._optimize_plugin(dest_path)

            metadata: dict[str, Any] = {
                "name": self.plugin_name,
                "version": self._get_version(),
                "build_time": datetime.now().isoformat(),
                "checksum": self._calculate_checksum(dest_path),
            }

            metadata_path: str = os.path.join(build_dir, f"{self.plugin_name}.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            result["artifacts"] = [dest_path, metadata_path]

        except Exception as e:
            logger.error("Exception in plugin_ci_cd: %s", e)
            result["success"] = False
            result_errors.append(f"Build error: {str(e)}")

        return result

    def run_deploy_stage(self) -> dict[str, Any]:
        """Deploy stage - deploy plugin to target.

        Deploys built plugin to target directory, backs up previous versions,
        and updates plugin registry.

        Returns:
            Dictionary with deployment paths and errors.
        """
        result: dict[str, Any] = {"success": True, "deployed_to": [], "errors": []}

        deploy_config: Any = self.pipeline_config.get("deploy", {})
        if not isinstance(deploy_config, dict):
            deploy_config = {"target": "local", "backup_previous": True}

        result_deployed_to: list[Any] = result["deployed_to"]
        result_errors: list[Any] = result["errors"]

        target: str = deploy_config.get("target", "local")
        if target == "local":
            plugin_install_dir: str = os.path.join(os.path.dirname(os.path.dirname(self.plugin_dir)), "plugins", "deployed")
            os.makedirs(plugin_install_dir, exist_ok=True)

            try:
                dest_path: str = os.path.join(plugin_install_dir, os.path.basename(self.plugin_path))

                backup_previous: bool = deploy_config.get("backup_previous", True)
                if os.path.exists(dest_path) and backup_previous:
                    backup_path: str = f"{dest_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    shutil.move(dest_path, backup_path)

                build_path: str = os.path.join(self.plugin_dir, "build", os.path.basename(self.plugin_path))
                shutil.copy2(build_path, dest_path)

                result_deployed_to.append(dest_path)

                self._update_plugin_registry(dest_path)

            except Exception as e:
                logger.error("Exception in plugin_ci_cd: %s", e)
                result["success"] = False
                result_errors.append(f"Deployment error: {str(e)}")

        return result

    def _check_syntax(self) -> dict[str, Any]:
        """Check plugin syntax.

        Validates Python plugin syntax using compile(). JavaScript plugins
        are considered valid without parsing.

        Returns:
            Dictionary with validity status and error messages.

        Raises:
            None: SyntaxError is caught and reported in result.
        """
        if not self.plugin_path.endswith(".py"):
            # For JavaScript, we'd need a JS parser
            return {"valid": True, "errors": []}
        try:
            with open(self.plugin_path) as f:
                compile(f.read(), self.plugin_path, "exec")
            return {"valid": True, "errors": []}
        except SyntaxError as e:
            logger.error("SyntaxError in plugin_ci_cd: %s", e)
            return {"valid": False, "errors": [f"Line {e.lineno}: {e.msg}"]}

    def _check_structure(self) -> dict[str, Any]:
        """Check plugin structure.

        Validates plugin structure using PluginStructureValidator.

        Returns:
            Structure validation result dictionary.

        Raises:
            ImportError: If PluginStructureValidator cannot be imported.
        """
        from ..utils.validation.import_validator import PluginStructureValidator

        return PluginStructureValidator.validate_structure_from_file(self.plugin_path)

    def _check_imports(self) -> dict[str, Any]:
        """Check plugin imports.

        Validates plugin imports using ImportValidator.

        Returns:
            Import validation result dictionary.

        Raises:
            ImportError: If ImportValidator cannot be imported.
        """
        from ..utils.validation.import_validator import ImportValidator

        return ImportValidator.validate_imports_from_file(self.plugin_path)

    def _run_linter(self, linter: str) -> dict[str, Any]:
        """Run a specific linter.

        Executes pylint or flake8 on the plugin and parses results.

        Args:
            linter: Linter name ('pylint' or 'flake8').

        Returns:
            Dictionary with success status and issues list.

        Raises:
            subprocess.CalledProcessError: Caught and logged, not re-raised.
            json.JSONDecodeError: Caught and logged, not re-raised.
        """
        result: dict[str, Any] = {"success": True, "issues": []}

        cmd: list[str]
        if linter == "flake8":
            cmd = ["flake8", self.plugin_path, "--format=json"]
        elif linter == "pylint":
            cmd = ["pylint", self.plugin_path, "--output-format=json"]
        else:
            return result

        result_issues: list[Any] = result["issues"]

        try:
            process: subprocess.CompletedProcess[str] = subprocess.run(cmd, capture_output=True, text=True)

            if process.stdout:
                issues: Any = json.loads(process.stdout)

                if isinstance(issues, list):
                    result_issues.extend(
                        issue.get("message", str(issue))
                        for issue in issues
                        if isinstance(issue, dict)
                        and issue.get("type") in ["error", "warning"]
                    )
                    if any(isinstance(issue, dict) and issue.get("type") == "error" for issue in issues):
                        result["success"] = False

        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.debug(f"Linter {linter} not available or output parsing failed: {e}")

        return result

    def _calculate_complexity(self) -> int:
        """Calculate cyclomatic complexity.

        Calculates cyclomatic complexity using Radon library.

        Returns:
            Maximum cyclomatic complexity value, or 0 if Radon unavailable.

        Raises:
            ImportError: Caught and logged when Radon not available.
        """
        try:
            import radon.complexity as cc

            with open(self.plugin_path) as f:
                code: str = f.read()

            if results := cc.cc_visit(code, self.plugin_path):
                if isinstance(results, list) and all(hasattr(item, 'complexity') for item in results):
                    return max(int(item.complexity) for item in results)

            return 0

        except ImportError as e:
            logger.debug(f"Radon not available for complexity calculation: {e}")
            return 0

    def _check_line_length(self) -> int:
        """Check maximum line length.

        Scans plugin file for longest line.

        Returns:
            Maximum line length found.

        Raises:
            IOError: If plugin file cannot be read.
        """
        max_length: int = 0

        with open(self.plugin_path) as f:
            for line in f:
                max_length = max(max_length, len(line.rstrip()))

        return max_length

    def _run_bandit(self) -> dict[str, Any]:
        """Run Bandit security scanner.

        Executes Bandit security scanner and parses JSON output.

        Returns:
            Dictionary with security issues found.

        Raises:
            subprocess.CalledProcessError: Caught and logged, not re-raised.
            json.JSONDecodeError: Caught and logged, not re-raised.
        """
        result: dict[str, Any] = {"issues": []}

        try:
            cmd: list[str] = ["bandit", "-f", "json", self.plugin_path]
            process: subprocess.CompletedProcess[str] = subprocess.run(cmd, capture_output=True, text=True)

            if process.stdout:
                data: Any = json.loads(process.stdout)

                if isinstance(data, dict):
                    results_list: Any = data.get("results", [])
                    if isinstance(results_list, list):
                        result_issues: list[Any] = result["issues"]
                        result_issues.extend(
                            {
                                "severity": issue.get("issue_severity"),
                                "confidence": issue.get("issue_confidence"),
                                "text": issue.get("issue_text"),
                                "line": issue.get("line_number"),
                            }
                            for issue in results_list
                            if isinstance(issue, dict)
                        )
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.debug(f"Bandit security scanner not available or failed: {e}")

        return result

    def _check_dependencies(self) -> dict[str, Any]:
        """Check for vulnerable dependencies.

        Checks for vulnerable dependencies. Currently returns empty result.

        Returns:
            Dictionary with vulnerable packages list.

        Raises:
            None: No exceptions raised in current implementation.
        """
        # This would integrate with a vulnerability database
        # For now, return empty
        return {"vulnerable_packages": []}

    def _optimize_plugin(self, file_path: str) -> None:
        """Optimize plugin code.

        Removes empty lines and comments from Python plugin code.

        Args:
            file_path: Path to plugin file to optimize.

        Raises:
            IOError: If plugin file cannot be read or written.
        """
        if file_path.endswith(".py"):
            with open(file_path) as f:
                lines: list[str] = f.readlines()

            optimized: list[str] = []
            for line in lines:
                stripped: str = line.strip()
                if stripped and not stripped.startswith("#"):
                    optimized.append(line)

            with open(file_path, "w") as f:
                f.writelines(optimized)

    def _get_version(self) -> str:
        """Get plugin version.

        Extracts version string from plugin code using regex.

        Returns:
            Plugin version string, or '1.0.0' if not found.

        Raises:
            IOError: Caught and logged if version extraction fails.
        """
        try:
            with open(self.plugin_path) as f:
                content: str = f.read()

            import re

            if match := re.search(r'version\s*=\s*["\']([^"\']+)["\']', content):
                return match.group(1)
        except Exception as e:
            logger.debug(f"Failed to extract plugin version: {e}")

        return "1.0.0"

    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate file checksum.

        Calculates SHA256 checksum of file.

        Args:
            file_path: Path to file.

        Returns:
            Hex-encoded SHA256 checksum.

        Raises:
            IOError: If file cannot be read.
        """
        sha256_hash: hashlib._Hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def _update_plugin_registry(self, plugin_path: str) -> None:
        """Update plugin registry with deployment info.

        Updates or creates plugin_registry.json with deployment information.

        Args:
            plugin_path: Path to deployed plugin file.

        Raises:
            IOError: If registry file cannot be read or written.
            json.JSONDecodeError: If existing registry is not valid JSON.
        """
        registry_path: str = os.path.join(os.path.dirname(plugin_path), "plugin_registry.json")

        registry: dict[str, Any]
        if os.path.exists(registry_path):
            with open(registry_path) as f:
                loaded_registry: Any = json.load(f)
                if isinstance(loaded_registry, dict):
                    registry = loaded_registry
                else:
                    registry = {"plugins": {}}
        else:
            registry = {"plugins": {}}

        plugins_dict: Any = registry.get("plugins", {})
        if isinstance(plugins_dict, dict):
            plugins_dict[self.plugin_name] = {
                "path": plugin_path,
                "deployed": datetime.now().isoformat(),
                "version": self._get_version(),
                "pipeline_run": self.results["timestamp"],
            }
            registry["plugins"] = plugins_dict

        with open(registry_path, "w") as f:
            json.dump(registry, f, indent=2)

    def _generate_report(self) -> None:
        """Generate pipeline report.

        Generates JSON and text format pipeline reports with stage results.

        Raises:
            IOError: If report files cannot be written.
        """
        report_path: str = os.path.join(self.plugin_dir, f"pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)

        overall_status: Any = self.results.get("overall_status", "unknown")
        timestamp: Any = self.results.get("timestamp", "")

        overall_status_str: str = str(overall_status).upper() if overall_status else "UNKNOWN"
        timestamp_str: str = str(timestamp) if timestamp else ""

        report_text: str = f"""
CI/CD Pipeline Report
====================
Plugin: {self.plugin_name}
Status: {overall_status_str}
Time: {timestamp_str}

Stage Results:
"""

        stages: Any = self.results.get("stages", {})
        if isinstance(stages, dict):
            for stage, result in stages.items():
                if isinstance(result, dict):
                    status: str = "OK PASSED" if result.get("success") else "ERROR FAILED"
                    report_text += f"\n{stage}: {status}"

                    errors: Any = result.get("errors")
                    if errors and isinstance(errors, list):
                        report_text += "\n  Errors:"
                        for error in errors:
                            report_text += f"\n    - {error}"

        report_text_path: str = report_path.replace(".json", ".txt")
        with open(report_text_path, "w") as f:
            f.write(report_text)


class GitHubActionsGenerator:
    """Generate GitHub Actions workflow for plugins.

    Creates GitHub Actions workflow YAML configuration files for
    automated CI/CD pipeline execution on GitHub.
    """

    @staticmethod
    def generate_workflow(plugin_name: str) -> str:
        """Generate GitHub Actions workflow YAML.

        Args:
            plugin_name: Name of the plugin for workflow configuration.

        Returns:
            GitHub Actions workflow YAML as string.

        Raises:
            None: No exceptions raised.
        """
        return f"""name: {plugin_name} CI/CD

on:
  push:
    branches: [ main, develop ]
    paths:
      - 'plugins/{plugin_name}/**'
  pull_request:
    branches: [ main ]
    paths:
      - 'plugins/{plugin_name}/**'

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.8', '3.9', '3.10']

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{{{ matrix.python-version }}}}
      uses: actions/setup-python@v4
      with:
        python-version: ${{{{ matrix.python-version }}}}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install pytest pytest-cov pytest-timeout
        pip install pylint flake8 bandit
        pip install -r requirements.txt

    - name: Run Intellicrack CI/CD Pipeline
      run: |
        python -m intellicrack.tools.plugin_ci_cd plugins/{plugin_name}/{plugin_name}.py

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella

    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: {plugin_name}-build
        path: plugins/{plugin_name}/build/
"""
