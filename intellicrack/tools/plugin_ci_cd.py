"""Plugin CI/CD system for automated plugin testing and deployment."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict

import yaml

from intellicrack.logger import logger

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


class CICDPipeline:
    """CI/CD pipeline for Intellicrack plugins"""

    def __init__(self, plugin_path: str):
        """Initialize CI/CD pipeline with plugin path, configuration, and results tracking."""
        self.plugin_path = plugin_path
        self.plugin_dir = os.path.dirname(plugin_path)
        self.plugin_name = os.path.basename(plugin_path).replace(".py", "").replace(".js", "")
        self.pipeline_config = self._load_or_create_config()
        self.results = {
            "stages": {},
            "overall_status": "pending",
            "timestamp": datetime.now().isoformat(),
        }

    def _load_or_create_config(self) -> Dict[str, Any]:
        """Load or create pipeline configuration"""
        config_path = os.path.join(self.plugin_dir, ".intellicrack-ci.yml")

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        else:
            # Create default config
            default_config = {
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

            # Save default config
            with open(config_path, "w") as f:
                yaml.dump(default_config, f, default_flow_style=False)

            return default_config

    def run_pipeline(self) -> Dict[str, Any]:
        """Run the complete CI/CD pipeline"""
        print(f"🚀 Starting CI/CD pipeline for {self.plugin_name}")

        for stage in self.pipeline_config["stages"]:
            if self.pipeline_config.get(stage, {}).get("enabled", True):
                print(f"\n📦 Running stage: {stage}")

                stage_result = getattr(self, f"run_{stage}_stage")()
                self.results["stages"][stage] = stage_result

                if not stage_result["success"]:
                    print(f"❌ Stage '{stage}' failed!")
                    self.results["overall_status"] = "failed"
                    break
                else:
                    print(f"✅ Stage '{stage}' passed!")
        else:
            self.results["overall_status"] = "success"

        # Generate report
        self._generate_report()

        return self.results

    def run_validate_stage(self) -> Dict[str, Any]:
        """Validation stage - check plugin structure"""
        result = {"success": True, "checks": {}, "errors": [], "warnings": []}

        checks = self.pipeline_config["validate"]["checks"]

        if "syntax" in checks:
            syntax_result = self._check_syntax()
            result["checks"]["syntax"] = syntax_result
            if not syntax_result["valid"]:
                result["success"] = False
                result["errors"].extend(syntax_result["errors"])

        if "structure" in checks:
            structure_result = self._check_structure()
            result["checks"]["structure"] = structure_result
            if not structure_result["valid"]:
                result["success"] = False
                result["errors"].extend(structure_result["errors"])

        if "imports" in checks:
            imports_result = self._check_imports()
            result["checks"]["imports"] = imports_result
            if imports_result["missing"]:
                result["warnings"].extend(imports_result["missing"])

        return result

    def run_test_stage(self) -> Dict[str, Any]:
        """Test stage - run unit tests"""
        result = {"success": True, "test_results": {}, "coverage": 0, "errors": []}

        test_config = self.pipeline_config["test"]

        # Find test file
        test_file = os.path.join(
            self.plugin_dir, "tests", f"test_{os.path.basename(self.plugin_path)}"
        )

        if not os.path.exists(test_file):
            # Generate tests if they don't exist
            from .plugin_test_generator import PluginTestGenerator

            generator = PluginTestGenerator()
            test_code = generator.generate_tests_for_file(self.plugin_path)

            os.makedirs(os.path.dirname(test_file), exist_ok=True)
            with open(test_file, "w") as f:
                f.write(test_code)

        # Run tests
        cmd = [
            sys.executable,
            "-m",
            test_config["framework"],
            test_file,
            "-v",
            f'--timeout={test_config["timeout"]}',
            "--tb=short",
        ]

        if test_config["framework"] == "pytest":
            cmd.extend([f"--cov={self.plugin_name}", "--cov-report=json"])

        try:
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=test_config["timeout"]
            )

            result["test_results"] = {
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
            }

            if process.returncode != 0:
                result["success"] = False
                result["errors"].append("Tests failed")

            # Parse coverage
            coverage_file = "coverage.json"
            if os.path.exists(coverage_file):
                with open(coverage_file, "r") as f:
                    coverage_data = json.load(f)
                    result["coverage"] = coverage_data.get("totals", {}).get("percent_covered", 0)

                if result["coverage"] < test_config["coverage_threshold"]:
                    result["success"] = False
                    result["errors"].append(
                        f"Coverage {result['coverage']}% below threshold {test_config['coverage_threshold']}%"
                    )

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in plugin_ci_cd: %s", e)
            result["success"] = False
            result["errors"].append(f"Tests timed out after {test_config['timeout']} seconds")
        except Exception as e:
            logger.error("Exception in plugin_ci_cd: %s", e)
            result["success"] = False
            result["errors"].append(f"Test execution error: {str(e)}")

        return result

    def run_quality_stage(self) -> Dict[str, Any]:
        """Quality stage - run linters and code quality checks"""
        result = {"success": True, "linter_results": {}, "metrics": {}, "errors": []}

        quality_config = self.pipeline_config["quality"]

        # Run linters
        for linter in quality_config["linters"]:
            linter_result = self._run_linter(linter)
            result["linter_results"][linter] = linter_result

            if not linter_result["success"]:
                result["success"] = False
                result["errors"].extend(linter_result["issues"])

        # Check code complexity
        complexity = self._calculate_complexity()
        result["metrics"]["complexity"] = complexity

        if complexity > quality_config["max_complexity"]:
            result["success"] = False
            result["errors"].append(
                f"Code complexity {complexity} exceeds maximum {quality_config['max_complexity']}"
            )

        # Check line length
        max_line_length = self._check_line_length()
        result["metrics"]["max_line_length"] = max_line_length

        if max_line_length > quality_config["max_line_length"]:
            result["errors"].append(
                f"Line length {max_line_length} exceeds maximum {quality_config['max_line_length']}"
            )

        return result

    def run_security_stage(self) -> Dict[str, Any]:
        """Security stage - run security scanners"""
        result = {"success": True, "scanner_results": {}, "vulnerabilities": [], "errors": []}

        security_config = self.pipeline_config["security"]

        # Run security scanners
        for scanner in security_config["scanners"]:
            if scanner == "bandit":
                scanner_result = self._run_bandit()
                result["scanner_results"][scanner] = scanner_result

                if scanner_result["issues"]:
                    result["vulnerabilities"].extend(scanner_result["issues"])
                    if any(issue["severity"] == "HIGH" for issue in scanner_result["issues"]):
                        result["success"] = False
                        result["errors"].append("High severity security issues found")

        # Check dependencies
        if security_config["check_dependencies"]:
            dep_result = self._check_dependencies()
            result["dependencies"] = dep_result

            if dep_result.get("vulnerable_packages"):
                result["vulnerabilities"].extend(dep_result["vulnerable_packages"])
                result["errors"].append("Vulnerable dependencies found")

        return result

    def run_build_stage(self) -> Dict[str, Any]:
        """Build stage - optimize and package plugin"""
        result = {"success": True, "artifacts": [], "errors": []}

        build_config = self.pipeline_config["build"]
        build_dir = os.path.join(self.plugin_dir, "build")
        os.makedirs(build_dir, exist_ok=True)

        try:
            # Copy plugin file
            dest_path = os.path.join(build_dir, os.path.basename(self.plugin_path))
            shutil.copy2(self.plugin_path, dest_path)

            # Optimize if requested
            if build_config["optimize"]:
                self._optimize_plugin(dest_path)

            # Create metadata file
            metadata = {
                "name": self.plugin_name,
                "version": self._get_version(),
                "build_time": datetime.now().isoformat(),
                "checksum": self._calculate_checksum(dest_path),
            }

            metadata_path = os.path.join(build_dir, f"{self.plugin_name}.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            result["artifacts"] = [dest_path, metadata_path]

        except Exception as e:
            logger.error("Exception in plugin_ci_cd: %s", e)
            result["success"] = False
            result["errors"].append(f"Build error: {str(e)}")

        return result

    def run_deploy_stage(self) -> Dict[str, Any]:
        """Deploy stage - deploy plugin to target"""
        result = {"success": True, "deployed_to": [], "errors": []}

        deploy_config = self.pipeline_config["deploy"]

        if deploy_config["target"] == "local":
            # Deploy to local plugin directory
            plugin_install_dir = os.path.join(
                os.path.dirname(os.path.dirname(self.plugin_dir)), "plugins", "deployed"
            )
            os.makedirs(plugin_install_dir, exist_ok=True)

            try:
                # Backup previous version if exists
                dest_path = os.path.join(plugin_install_dir, os.path.basename(self.plugin_path))

                if os.path.exists(dest_path) and deploy_config["backup_previous"]:
                    backup_path = dest_path + f'.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                    shutil.move(dest_path, backup_path)

                # Copy from build directory
                build_path = os.path.join(
                    self.plugin_dir, "build", os.path.basename(self.plugin_path)
                )
                shutil.copy2(build_path, dest_path)

                result["deployed_to"].append(dest_path)

                # Update plugin registry
                self._update_plugin_registry(dest_path)

            except Exception as e:
                logger.error("Exception in plugin_ci_cd: %s", e)
                result["success"] = False
                result["errors"].append(f"Deployment error: {str(e)}")

        return result

    def _check_syntax(self) -> Dict[str, Any]:
        """Check plugin syntax"""
        if self.plugin_path.endswith(".py"):
            try:
                with open(self.plugin_path, "r") as f:
                    compile(f.read(), self.plugin_path, "exec")
                return {"valid": True, "errors": []}
            except SyntaxError as e:
                logger.error("SyntaxError in plugin_ci_cd: %s", e)
                return {"valid": False, "errors": [f"Line {e.lineno}: {e.msg}"]}
        else:
            # For JavaScript, we'd need a JS parser
            return {"valid": True, "errors": []}

    def _check_structure(self) -> Dict[str, Any]:
        """Check plugin structure"""
        from ..utils.validation.import_validator import PluginStructureValidator

        return PluginStructureValidator.validate_structure_from_file(self.plugin_path)

    def _check_imports(self) -> Dict[str, Any]:
        """Check plugin imports"""
        from ..utils.validation.import_validator import ImportValidator

        return ImportValidator.validate_imports_from_file(self.plugin_path)

    def _run_linter(self, linter: str) -> Dict[str, Any]:
        """Run a specific linter"""
        result = {"success": True, "issues": []}

        if linter == "pylint":
            cmd = ["pylint", self.plugin_path, "--output-format=json"]
        elif linter == "flake8":
            cmd = ["flake8", self.plugin_path, "--format=json"]
        else:
            return result

        try:
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.stdout:
                issues = json.loads(process.stdout)

                # Filter by severity
                for issue in issues:
                    if issue.get("type") in ["error", "warning"]:
                        result["issues"].append(issue.get("message", str(issue)))

                if any(issue.get("type") == "error" for issue in issues):
                    result["success"] = False

        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.debug(f"Linter {linter} not available or output parsing failed: {e}")

        return result

    def _calculate_complexity(self) -> int:
        """Calculate cyclomatic complexity"""
        try:
            import radon.complexity as cc

            with open(self.plugin_path, "r") as f:
                code = f.read()

            results = cc.cc_visit(code, self.plugin_path)

            if results:
                return max(item.complexity for item in results)

            return 0

        except ImportError as e:
            logger.debug(f"Radon not available for complexity calculation: {e}")
            # Radon not available
            return 0

    def _check_line_length(self) -> int:
        """Check maximum line length"""
        max_length = 0

        with open(self.plugin_path, "r") as f:
            for line in f:
                max_length = max(max_length, len(line.rstrip()))

        return max_length

    def _run_bandit(self) -> Dict[str, Any]:
        """Run Bandit security scanner"""
        result = {"issues": []}

        try:
            cmd = ["bandit", "-f", "json", self.plugin_path]
            process = subprocess.run(cmd, capture_output=True, text=True)

            if process.stdout:
                data = json.loads(process.stdout)

                for issue in data.get("results", []):
                    result["issues"].append(
                        {
                            "severity": issue.get("issue_severity"),
                            "confidence": issue.get("issue_confidence"),
                            "text": issue.get("issue_text"),
                            "line": issue.get("line_number"),
                        }
                    )

        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.debug(f"Bandit security scanner not available or failed: {e}")

        return result

    def _check_dependencies(self) -> Dict[str, Any]:
        """Check for vulnerable dependencies"""
        # This would integrate with a vulnerability database
        # For now, return empty
        return {"vulnerable_packages": []}

    def _optimize_plugin(self, file_path: str):
        """Optimize plugin code"""
        if file_path.endswith(".py"):
            # For Python, we could use tools like python-minifier
            # For now, just remove comments and empty lines
            with open(file_path, "r") as f:
                lines = f.readlines()

            optimized = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    optimized.append(line)

            with open(file_path, "w") as f:
                f.writelines(optimized)

    def _get_version(self) -> str:
        """Get plugin version"""
        # Try to extract from plugin code
        try:
            with open(self.plugin_path, "r") as f:
                content = f.read()

            import re

            match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                return match.group(1)
        except Exception as e:
            logger.debug(f"Failed to extract plugin version: {e}")

        return "1.0.0"

    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate file checksum"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def _update_plugin_registry(self, plugin_path: str):
        """Update plugin registry with deployment info"""
        registry_path = os.path.join(os.path.dirname(plugin_path), "plugin_registry.json")

        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                registry = json.load(f)
        else:
            registry = {"plugins": {}}

        registry["plugins"][self.plugin_name] = {
            "path": plugin_path,
            "deployed": datetime.now().isoformat(),
            "version": self._get_version(),
            "pipeline_run": self.results["timestamp"],
        }

        with open(registry_path, "w") as f:
            json.dump(registry, f, indent=2)

    def _generate_report(self):
        """Generate pipeline report"""
        report_path = os.path.join(
            self.plugin_dir, f'pipeline_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )

        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)

        # Also generate human-readable report
        report_text = f"""
CI/CD Pipeline Report
====================
Plugin: {self.plugin_name}
Status: {self.results['overall_status'].upper()}
Time: {self.results['timestamp']}

Stage Results:
"""

        for stage, result in self.results["stages"].items():
            status = "✅ PASSED" if result["success"] else "❌ FAILED"
            report_text += f"\n{stage}: {status}"

            if result.get("errors"):
                report_text += "\n  Errors:"
                for error in result["errors"]:
                    report_text += f"\n    - {error}"

        report_text_path = report_path.replace(".json", ".txt")
        with open(report_text_path, "w") as f:
            f.write(report_text)


class GitHubActionsGenerator:
    """Generate GitHub Actions workflow for plugins"""

    @staticmethod
    def generate_workflow(plugin_name: str) -> str:
        """Generate GitHub Actions workflow YAML"""
        workflow = f"""name: {plugin_name} CI/CD

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
        return workflow
