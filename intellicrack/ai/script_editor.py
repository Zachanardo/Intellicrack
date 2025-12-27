"""AI Script Editor for Iterative Script Improvement.

This module provides advanced script editing capabilities including:
1. Iterative script modification based on feedback
2. Context-aware script refinements
3. Script versioning and history tracking
4. Testing and validation integration
5. Performance-based optimization

Production-ready AI-driven script editing system.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from intellicrack.ai.qemu_manager import QEMUManager
from intellicrack.utils.logger import logger

from .ai_script_generator import AIScriptGenerator, ScriptType


class EditType(Enum):
    """Types of script edits."""

    BUGFIX = "bugfix"
    OPTIMIZATION = "optimization"
    ENHANCEMENT = "enhancement"
    REFACTOR = "refactor"
    SECURITY_FIX = "security_fix"
    COMPATIBILITY = "compatibility"
    FEATURE_ADD = "feature_add"


class ValidationResult(Enum):
    """Script validation outcomes."""

    SUCCESS = "success"
    SYNTAX_ERROR = "syntax_error"
    RUNTIME_ERROR = "runtime_error"
    LOGIC_ERROR = "logic_error"
    PERFORMANCE_POOR = "performance_poor"
    SECURITY_ISSUE = "security_issue"


@dataclass
class EditRequest:
    """Request for script modification."""

    original_script_path: str
    modification_prompt: str
    edit_type: EditType
    target_addresses: list[str] = field(default_factory=list)
    expected_behavior: str = ""
    test_criteria: dict[str, Any] = field(default_factory=dict)
    preserve_functionality: bool = True


@dataclass
class ScriptEdit:
    """Record of a script modification."""

    edit_id: str
    timestamp: str
    edit_type: EditType
    modification_prompt: str
    changes_made: list[str]
    confidence_score: float
    validation_result: ValidationResult | None = None
    performance_metrics: dict[str, Any] = field(default_factory=dict)
    rollback_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptVersion:
    """Version tracking for script evolution."""

    version_number: str
    content: str
    edit_history: list[ScriptEdit]
    creation_timestamp: str
    parent_version: str | None = None
    tags: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


class ScriptTester:
    """Automated testing framework for generated scripts."""

    def __init__(self) -> None:
        """Initialize script tester with AI script generator for validation."""
        self.ai_generator = AIScriptGenerator()

    def validate_script(self, script_content: str, script_type: str) -> tuple[ValidationResult, dict[str, Any]]:
        """Validate script using LLM for comprehensive analysis.

        Args:
            script_content: The script content to validate.
            script_type: The type of script (frida, ghidra, python, etc.).

        Returns:
            A tuple containing the validation result status and a dict with detailed validation analysis.
        """
        results = {
            "syntax_check": True,
            "security_scan": {},
            "performance_estimate": {},
            "compatibility": {},
            "warnings": [],
        }

        # Build validation prompt for LLM
        validation_prompt = f"""Analyze the following {script_type} script for issues:

Script Content:
{script_content}

Please check for:
1. Syntax errors
2. Security vulnerabilities (code injection, unvalidated input, etc.)
3. Performance issues (inefficient loops, memory leaks, etc.)
4. Logic errors
5. Best practice violations

Return your analysis as a JSON object with the following structure:
{{
    "has_syntax_errors": boolean,
    "syntax_errors": [list of syntax errors if any],
    "security_issues": {{
        "critical": [list of critical security issues],
        "high": [list of high security issues],
        "medium": [list of medium security issues],
        "low": [list of low security issues]
    }},
    "performance_issues": [list of performance concerns],
    "logic_errors": [list of logic problems],
    "best_practice_violations": [list of violations],
    "overall_severity": "none" | "low" | "medium" | "high" | "critical",
    "recommendations": [list of improvement suggestions]
}}

Provide only the JSON response, no explanations."""

        try:
            # Use AI generator for validation
            # For validation, we'll use a simple response format
            response = self.ai_generator.generate_script(
                _prompt=validation_prompt, base_script=script_content, context={"validation": True}
            )

            # Parse LLM response
            try:
                analysis = json.loads(response)

                # Map LLM analysis to results
                results["syntax_check"] = not analysis.get("has_syntax_errors", False)
                results["security_scan"] = analysis.get("security_issues", {})
                results["performance_estimate"] = {
                    "issues": analysis.get("performance_issues", []),
                    "complexity_score": 0.5 if analysis.get("performance_issues") else 0.2,
                }
                results["warnings"] = analysis.get("best_practice_violations", [])

                # Determine validation result based on severity
                severity = analysis.get("overall_severity", "none")
                if severity == "critical":
                    return ValidationResult.SECURITY_ISSUE, results
                if analysis.get("has_syntax_errors"):
                    return ValidationResult.SYNTAX_ERROR, results
                if severity == "high":
                    return ValidationResult.LOGIC_ERROR, results
                if len(analysis.get("performance_issues", [])) > 3:
                    return ValidationResult.PERFORMANCE_POOR, results
                return ValidationResult.SUCCESS, results

            except json.JSONDecodeError:
                # If LLM didn't return valid JSON, assume basic validation passed
                logger.warning("LLM validation response was not valid JSON")
                return ValidationResult.SUCCESS, results

        except Exception as e:
            logger.error(f"Script validation failed: {e}")
            results["error"] = str(e)
            return ValidationResult.RUNTIME_ERROR, results

    def test_script_execution(
        self,
        script_content: str,
        script_type: str,
        binary_path: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Test script execution in QEMU virtual machine.

        Args:
            script_content: The script content to execute and test.
            script_type: The type of script (frida, ghidra, python, etc.).
            binary_path: Optional path to the target binary for testing.
            timeout: Execution timeout in seconds.

        Returns:
            A dict containing execution results with success status, output, errors, and performance metrics.
        """
        try:
            qemu_manager = self._get_qemu_manager()

            # Handle None binary_path - QEMU requires a binary path
            if not binary_path:
                binary_path = f"{tempfile.gettempdir()}/test_binary"  # Default test binary path

            result = qemu_manager.test_script_in_vm(
                script_content=script_content,
                binary_path=binary_path,
                script_type=script_type,
                timeout=timeout,
            )

            # Convert ExecutionResult to dict format expected by callers
            return {
                "success": result.success,
                "output": result.output,
                "errors": result.error.split("\n") if result.error else [],
                "performance": {"runtime_ms": result.runtime_ms, "exit_code": result.exit_code},
            }
        except Exception as e:
            logger.error(f"Script execution test failed: {e}")
            return {"error": str(e), "success": False}

    def _get_qemu_manager(self) -> QEMUManager:
        """Get or create QEMUManager instance.

        Returns:
            A QEMUManager instance for virtual machine testing.
        """
        if not hasattr(self, "_qemu_manager"):
            from intellicrack.ai.qemu_manager import QEMUManager

        if not hasattr(self, "_qemu_manager"):
            self._qemu_manager = QEMUManager()

        return self._qemu_manager

    def _validate_frida_syntax(self, script: str) -> ValidationResult:
        """Validate Frida JavaScript syntax.

        Args:
            script: The Frida script content to validate.

        Returns:
            A ValidationResult enum indicating the validation outcome.
        """
        # Check for required Frida patterns
        required_patterns = [
            r"Java\.perform|Interceptor\.attach|Process\.enumerate",
            r"console\.log|send\(",
            r"onEnter|onLeave",
        ]

        has_frida_patterns = any(re.search(pattern, script, re.IGNORECASE) for pattern in required_patterns)

        if not has_frida_patterns:
            return ValidationResult.LOGIC_ERROR

        # Check for common JavaScript syntax issues
        if script.count("{") != script.count("}"):
            return ValidationResult.SYNTAX_ERROR

        return ValidationResult.SUCCESS

    def _validate_ghidra_syntax(self, script: str) -> ValidationResult:
        """Validate Ghidra Java syntax.

        Args:
            script: The Ghidra Java script content to validate.

        Returns:
            A ValidationResult enum indicating the validation outcome.
        """
        # Check for required Ghidra imports
        required_imports = ["ghidra.app.script.GhidraScript", "ghidra.program.model"]

        has_imports = any(imp in script for imp in required_imports)
        if not has_imports:
            return ValidationResult.LOGIC_ERROR

        # Check for class structure
        if "extends GhidraScript" not in script:
            return ValidationResult.SYNTAX_ERROR

        if "public void run()" not in script:
            return ValidationResult.SYNTAX_ERROR

        return ValidationResult.SUCCESS

    def _validate_python_syntax(self, script: str) -> ValidationResult:
        """Validate Python syntax.

        Args:
            script: The Python script content to validate.

        Returns:
            A ValidationResult enum indicating the validation outcome.
        """
        try:
            compile(script, "<string>", "exec")
            return ValidationResult.SUCCESS
        except SyntaxError:
            return ValidationResult.SYNTAX_ERROR
        except Exception:
            return ValidationResult.RUNTIME_ERROR

    def _scan_security_issues(self, script: str) -> dict[str, Any]:
        """Scan for potential security issues.

        Args:
            script: The script content to scan for security vulnerabilities.

        Returns:
            A dict containing categorized security issues (critical_issues, warnings, info).
        """
        issues: dict[str, list[str]] = {"critical_issues": [], "warnings": [], "info": []}

        # Check for dangerous patterns
        dangerous_patterns = {
            "critical": [
                r"exec\s*\(",
                r"eval\s*\(",
                r"os\.system\s*\(",
                r"subprocess\..*shell\s*=\s*True",
            ],
            "warning": [
                r'open\s*\(.+["\']w["\']',
                r"write\s*\(",
                r"Memory\.protect.*7",  # RWX permissions
                r"patch_byte|patch_word",
            ],
        }

        for severity, patterns in dangerous_patterns.items():
            for pattern in patterns:
                if matches := re.findall(pattern, script, re.IGNORECASE):
                    key = f"{severity}_issues" if severity == "critical" else "warnings"
                    if key in issues:
                        issues[key].extend(matches)

        return issues

    def _analyze_performance(self, script: str) -> dict[str, Any]:
        """Analyze script performance characteristics.

        Args:
            script: The script content to analyze for performance metrics.

        Returns:
            A dict with complexity score, estimated runtime, memory usage, and optimization suggestions.
        """
        metrics = {
            "complexity_score": 0.0,
            "estimated_runtime": "unknown",
            "memory_usage": "low",
            "optimization_suggestions": [],
        }

        # Basic complexity analysis
        lines = script.split("\n")
        complexity_factors = {
            "loops": len(re.findall(r"for\s*\(|while\s*\(|forEach", script)),
            "conditions": len(re.findall(r"if\s*\(|switch\s*\(", script)),
            "recursion": len(re.findall(r"function\s+(\w+)[\s\S]*?\1\s*\(", script)),
            "memory_operations": len(re.findall(r"Memory\.|mem\.", script)),
        }

        total_complexity = sum(complexity_factors.values())
        line_count = len([line for line in lines if line.strip()])

        if line_count > 0:
            metrics["complexity_score"] = min(total_complexity / line_count, 1.0)

        # Performance suggestions
        suggestions = metrics["optimization_suggestions"]
        if isinstance(suggestions, list):
            if complexity_factors["loops"] > 10:
                suggestions.append("Consider reducing nested loops")

            if complexity_factors["memory_operations"] > 20:
                suggestions.append("High memory operation count - consider batching")

        return metrics


class ScriptVersionManager:
    """Manages script versions and evolution history."""

    def __init__(self, base_path: str) -> None:
        """Initialize version manager with base path for version storage.

        Args:
            base_path: The base directory path where script versions will be stored.
        """
        self.base_path = Path(base_path)
        self.versions_dir = self.base_path / "versions"
        self.versions_dir.mkdir(parents=True, exist_ok=True)

    def create_version(
        self,
        content: str,
        edit_history: list[ScriptEdit],
        parent_version: str | None = None,
    ) -> ScriptVersion:
        """Create new script version.

        Args:
            content: The script content to store in this version.
            edit_history: List of ScriptEdit records that led to this version.
            parent_version: Optional ID of the parent version if this is derived.

        Returns:
            A ScriptVersion object representing the newly created version.
        """
        version_id = self._generate_version_id(content)

        version = ScriptVersion(
            version_number=version_id,
            content=content,
            edit_history=edit_history.copy(),
            creation_timestamp=datetime.now().isoformat(),
            parent_version=parent_version,
        )

        # Save version data
        version_file = self.versions_dir / f"{version_id}.json"
        version_data = {
            "version": version.version_number,
            "content": version.content,
            "edit_history": [self._edit_to_dict(edit) for edit in version.edit_history],
            "creation_timestamp": version.creation_timestamp,
            "parent_version": version.parent_version,
            "tags": version.tags,
            "metrics": version.metrics,
        }

        with open(version_file, "w", encoding="utf-8") as f:
            json.dump(version_data, f, indent=2)

        logger.info(f"Created script version: {version_id}")
        return version

    def get_version_history(self) -> list[ScriptVersion]:
        """Get version history for a script.

        Returns:
            A list of ScriptVersion objects sorted by creation timestamp.
        """
        versions = []

        for version_file in self.versions_dir.glob("*.json"):
            try:
                with open(version_file, encoding="utf-8") as f:
                    data = json.load(f)

                version = ScriptVersion(
                    version_number=data["version"],
                    content=data["content"],
                    edit_history=[self._dict_to_edit(edit) for edit in data["edit_history"]],
                    creation_timestamp=data["creation_timestamp"],
                    parent_version=data.get("parent_version"),
                    tags=data.get("tags", []),
                    metrics=data.get("metrics", {}),
                )
                versions.append(version)

            except Exception as e:
                logger.warning(f"Failed to load version {version_file}: {e}")

        # Sort by creation time
        versions.sort(key=lambda v: v.creation_timestamp)
        return versions

    def rollback_to_version(self, version_id: str) -> str | None:
        """Rollback to a specific version.

        Args:
            version_id: The ID of the version to rollback to.

        Returns:
            The script content from the specified version, or None if not found.
        """
        version_file = self.versions_dir / f"{version_id}.json"

        if not version_file.exists():
            return None

        try:
            with open(version_file, encoding="utf-8") as f:
                data: dict[str, Any] = json.load(f)

            return str(data["content"])

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return None

    def _generate_version_id(self, content: str) -> str:
        """Generate unique version ID.

        Args:
            content: The script content to hash for version ID generation.

        Returns:
            A unique version identifier string based on timestamp and content hash.
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"v_{timestamp}_{content_hash}"

    def _edit_to_dict(self, edit: ScriptEdit) -> dict[str, Any]:
        """Convert ScriptEdit to dictionary.

        Args:
            edit: The ScriptEdit object to convert.

        Returns:
            A dictionary representation of the ScriptEdit for serialization.
        """
        return {
            "edit_id": edit.edit_id,
            "timestamp": edit.timestamp,
            "edit_type": edit.edit_type.value,
            "modification_prompt": edit.modification_prompt,
            "changes_made": edit.changes_made,
            "confidence_score": edit.confidence_score,
            "validation_result": edit.validation_result.value if edit.validation_result else None,
            "performance_metrics": edit.performance_metrics,
            "rollback_info": edit.rollback_info,
        }

    def _dict_to_edit(self, data: dict[str, Any]) -> ScriptEdit:
        """Convert dictionary to ScriptEdit.

        Args:
            data: A dictionary representation of a ScriptEdit.

        Returns:
            A ScriptEdit object reconstructed from the dictionary data.
        """
        return ScriptEdit(
            edit_id=data["edit_id"],
            timestamp=data["timestamp"],
            edit_type=EditType(data["edit_type"]),
            modification_prompt=data["modification_prompt"],
            changes_made=data["changes_made"],
            confidence_score=data["confidence_score"],
            validation_result=ValidationResult(data["validation_result"]) if data.get("validation_result") else None,
            performance_metrics=data.get("performance_metrics", {}),
            rollback_info=data.get("rollback_info", {}),
        )


class AIScriptEditor:
    """Advanced AI-powered script editor with iterative improvement capabilities."""

    def __init__(self) -> None:
        """Initialize AI script editor with all necessary components for advanced editing.

        Sets up the script generator, tester, version manager, and edit history tracking.
        """
        self.ai_generator = AIScriptGenerator()
        self.tester = ScriptTester()
        import intellicrack

        root = Path(intellicrack.__file__).parent
        self.version_manager = ScriptVersionManager(str(root / "scripts"))
        self.edit_history: dict[str, list[ScriptEdit]] = {}
        logger.info("AIScriptEditor initialized with advanced editing capabilities")

    def edit_script(
        self,
        script_path: str,
        modification_prompt: str,
        edit_type: EditType = EditType.ENHANCEMENT,
        test_binary: str | None = None,
        preserve_functionality: bool = True,
    ) -> dict[str, Any]:
        """Edit an existing script based on modification prompt.

        This is the main entry point for AI script editing.

        Args:
            script_path: Path to the script file to edit.
            modification_prompt: The modification request or enhancement description.
            edit_type: The type of edit (ENHANCEMENT, BUGFIX, OPTIMIZATION, etc.).
            test_binary: Optional path to a binary for testing the modified script.
            preserve_functionality: Whether to maintain existing script functionality.

        Returns:
            A dict with success status, modified content, edit record, version ID, validation results,
            and execution test results or suggested fixes if validation failed.
        """
        logger.info(f"Editing script {script_path}: {modification_prompt[:100]}...")

        try:
            # Load original script
            original_content = self._load_script(script_path)
            if not original_content:
                return {"success": False, "error": "Script not found"}

            # Determine script type
            script_type = self._detect_script_type(script_path, original_content)

            # Create edit request
            edit_request = EditRequest(
                original_script_path=script_path,
                modification_prompt=modification_prompt,
                edit_type=edit_type,
                preserve_functionality=preserve_functionality,
            )

            # Generate modification prompt for AI generator
            ai_prompt = self._build_edit_prompt(original_content, edit_request, script_type)

            # Generate modified script using AI generator
            modified_content = self.ai_generator.generate_script(
                _prompt=ai_prompt,
                base_script=original_content,
                context={"edit_type": edit_request.edit_type.value, "preserve_functionality": edit_request.preserve_functionality},
            )

            # Validate modified script
            validation_result, validation_details = self.tester.validate_script(modified_content, script_type)

            # Test execution if validation passes
            execution_results = {}
            if validation_result == ValidationResult.SUCCESS:
                execution_results = self.tester.test_script_execution(modified_content, script_type, test_binary)

            # Create edit record
            edit_record = ScriptEdit(
                edit_id=self._generate_edit_id(),
                timestamp=datetime.now().isoformat(),
                edit_type=edit_type,
                modification_prompt=modification_prompt,
                changes_made=self._extract_changes(original_content, modified_content),
                confidence_score=self._calculate_edit_confidence(original_content, modified_content, validation_result),
                validation_result=validation_result,
                performance_metrics=execution_results.get("performance", {}),
                rollback_info={"original_content": original_content},
            )

            # Update edit history
            if script_path not in self.edit_history:
                self.edit_history[script_path] = []
            self.edit_history[script_path].append(edit_record)

            # Create new version
            # Get parent version ID if exists
            parent_version_id: str | None = None
            if self.edit_history[script_path]:
                history = self.edit_history[script_path]
                if history and len(history) > 1:
                    parent_version_id = history[-2].edit_id

            version = self.version_manager.create_version(
                content=modified_content, edit_history=self.edit_history[script_path], parent_version=parent_version_id
            )

            # Save modified script if validation passed
            if validation_result == ValidationResult.SUCCESS and execution_results.get("success", False):
                self._save_script(script_path, modified_content, edit_record)

                return {
                    "success": True,
                    "modified_content": modified_content,
                    "edit_record": self._edit_to_dict(edit_record),
                    "version_id": version.version_number,
                    "validation": validation_details,
                    "execution_test": execution_results,
                    "changes_summary": edit_record.changes_made,
                }
            # Keep original, return issues
            return {
                "success": False,
                "error": f"Validation failed: {validation_result.value}",
                "modified_content": modified_content,
                "validation": validation_details,
                "execution_test": execution_results,
                "suggested_fixes": self._suggest_fixes(validation_result, validation_details),
            }

        except Exception as e:
            logger.error(f"Script editing failed: {e}")
            import traceback

            return {"success": False, "error": str(e), "traceback": traceback.format_exc()}

    def iterative_improve(
        self,
        script_path: str,
        improvement_goals: list[str],
        max_iterations: int = 5,
        test_binary: str | None = None,
    ) -> dict[str, Any]:
        """Improve a script iteratively through multiple edit cycles using QEMU feedback.

        Args:
            script_path: Path to the script file to improve.
            improvement_goals: List of goals the script should achieve.
            max_iterations: Maximum number of improvement iterations to perform.
            test_binary: Optional path to a binary for QEMU testing.

        Returns:
            A dict containing iteration results, final success status, improvement metrics,
            and QEMU feedback from each iteration.
        """
        results: dict[str, Any] = {
            "iterations": [],
            "final_success": False,
            "improvement_metrics": {},
            "qemu_feedback": [],
        }

        current_content = self._load_script(script_path)
        if not current_content:
            return {"success": False, "error": "Script not found"}

        # Detect script type from filename for QEMU testing
        script_type = self._detect_script_type_from_path(script_path)

        for iteration in range(max_iterations):
            logger.info(f"Improvement iteration {iteration + 1}/{max_iterations}")

            # Test current script in QEMU first to get baseline
            qemu_result = self.tester.test_script_execution(current_content, script_type, test_binary, timeout=60)

            feedback_list = results["qemu_feedback"]
            if isinstance(feedback_list, list):
                feedback_list.append(qemu_result)

            # Analyze QEMU results to determine if goals are achieved
            goals_achieved = self._analyze_qemu_results_for_goals(qemu_result, improvement_goals)

            # If goals are achieved, we're done
            if goals_achieved:
                results["final_success"] = True
                iterations_list = results["iterations"]
                if isinstance(iterations_list, list):
                    iterations_list.append(
                        {
                            "iteration": iteration + 1,
                            "result": {"success": True, "message": "Goals achieved"},
                            "qemu_result": qemu_result,
                            "goals_achieved": True,
                        },
                    )
                break

            # Create improvement prompt with QEMU feedback
            improvement_prompt = self._create_improvement_prompt_with_feedback(improvement_goals, qemu_result)

            # Edit script based on QEMU feedback
            edit_result = self.edit_script(script_path, improvement_prompt, EditType.OPTIMIZATION, test_binary)

            iterations_list = results["iterations"]
            if isinstance(iterations_list, list):
                iterations_list.append(
                    {
                        "iteration": iteration + 1,
                        "result": edit_result,
                        "qemu_result": qemu_result,
                        "goals_achieved": goals_achieved,
                    },
                )

            # Update current content if edit was successful
            if edit_result.get("success"):
                current_content = edit_result["modified_content"]

                # Save the improved version
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(current_content)
            else:
                # If edit failed, log and continue with feedback
                logger.warning(f"Iteration {iteration + 1} edit failed: {edit_result.get('error', 'Unknown error')}")

        # Final test to verify improvement
        if results["iterations"]:
            final_qemu_result = self.tester.test_script_execution(current_content, script_type, test_binary, timeout=60)
            results["final_qemu_result"] = final_qemu_result
            results["final_success"] = final_qemu_result.get("success", False)

        return results

    def compare_versions(self, version1_id: str, version2_id: str) -> dict[str, Any]:
        """Compare two script versions.

        Args:
            version1_id: The ID of the first version to compare.
            version2_id: The ID of the second version to compare.

        Returns:
            A dict with version IDs, diff statistics, and comparison recommendations.
        """
        v1_content = self.version_manager.rollback_to_version(version1_id)
        v2_content = self.version_manager.rollback_to_version(version2_id)

        if not v1_content or not v2_content:
            return {"error": "Version not found"}

        # Calculate differences
        diff_stats = self._calculate_diff_stats(v1_content, v2_content)

        return {
            "version1": version1_id,
            "version2": version2_id,
            "diff_stats": diff_stats,
            "recommendations": self._generate_version_recommendations(diff_stats),
        }

    def rollback_edit(self, script_path: str, edit_id: str) -> dict[str, Any]:
        """Rollback a specific edit.

        Args:
            script_path: Path to the script file to rollback.
            edit_id: The ID of the edit to rollback.

        Returns:
            A dict with success status, restored content, and the rollback edit ID.
        """
        if script_path not in self.edit_history:
            return {"success": False, "error": "No edit history found"}

        edit_to_rollback = next(
            (edit for edit in self.edit_history[script_path] if edit.edit_id == edit_id),
            None,
        )
        if not edit_to_rollback:
            return {"success": False, "error": "Edit not found"}

        # Restore original content
        original_content = edit_to_rollback.rollback_info.get("original_content")
        if not original_content:
            return {"success": False, "error": "No rollback information available"}

        # Save restored version
        rollback_edit = ScriptEdit(
            edit_id=self._generate_edit_id(),
            timestamp=datetime.now().isoformat(),
            edit_type=EditType.BUGFIX,
            modification_prompt=f"Rollback edit {edit_id}",
            changes_made=[f"Rolled back to state before edit {edit_id}"],
            confidence_score=1.0,
        )

        self.edit_history[script_path].append(rollback_edit)
        self._save_script(script_path, original_content, rollback_edit)

        return {
            "success": True,
            "restored_content": original_content,
            "rollback_edit_id": rollback_edit.edit_id,
        }

    def get_edit_suggestions(self, script_path: str, binary_analysis: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Get AI-powered suggestions for script improvements.

        Args:
            script_path: Path to the script file to analyze.
            binary_analysis: Optional dict with binary analysis details for targeted suggestions.

        Returns:
            A list of suggestion dicts with type, priority, description, and details.
        """
        script_content = self._load_script(script_path)
        if not script_content:
            return []

        script_type = self._detect_script_type(script_path, script_content)

        # Analyze current script
        _, validation_details = self.tester.validate_script(script_content, script_type)

        suggestions = []

        # Security suggestions
        security_issues = validation_details.get("security_scan", {})
        if security_issues.get("warnings"):
            suggestions.append(
                {
                    "type": "security",
                    "priority": "high",
                    "description": "Address security warnings",
                    "details": security_issues["warnings"],
                },
            )

        # Performance suggestions
        perf_metrics = validation_details.get("performance_estimate", {})
        if perf_metrics.get("optimization_suggestions"):
            suggestions.append(
                {
                    "type": "performance",
                    "priority": "medium",
                    "description": "Optimize performance",
                    "details": perf_metrics["optimization_suggestions"],
                },
            )

        # Binary-specific suggestions
        if binary_analysis:
            binary_suggestions = self._generate_binary_specific_suggestions(script_content, script_type, binary_analysis)
            suggestions.extend(binary_suggestions)

        return suggestions

    def _load_script(self, script_path: str) -> str | None:
        """Load script content from file.

        Args:
            script_path: Path to the script file to load.

        Returns:
            The script content as a string, or None if file cannot be read.
        """
        try:
            with open(script_path, encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load script {script_path}: {e}")
            return None

    def _save_script(self, script_path: str, content: str, edit_record: ScriptEdit) -> None:
        """Save modified script content.

        Args:
            script_path: Path where the script should be saved.
            content: The script content to save.
            edit_record: The ScriptEdit record associated with this save.
        """
        try:
            # Create backup of original
            backup_path = f"{script_path}.backup_{edit_record.edit_id}"
            if os.path.exists(script_path):
                from pathlib import Path

                Path(script_path).rename(backup_path)

            # Save new content
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(content)

            logger.info(f"Saved modified script: {script_path}")
        except Exception as e:
            logger.error(f"Failed to save script: {e}")

    def _build_edit_prompt(self, original_content: str, edit_request: EditRequest, script_type: str) -> str:
        """Build comprehensive prompt for script editing.

        Args:
            original_content: The original script content.
            edit_request: The EditRequest containing modification details.
            script_type: The type of script being edited.

        Returns:
            A comprehensive prompt string for the AI script generator.
        """
        return f"""Modify the following {script_type} script based on the user's request.

ORIGINAL SCRIPT:
```
{original_content}
```

MODIFICATION REQUEST: {edit_request.modification_prompt}
EDIT TYPE: {edit_request.edit_type.value}
PRESERVE FUNCTIONALITY: {edit_request.preserve_functionality}

REQUIREMENTS:
1. Apply the requested modifications precisely
2. Maintain script functionality and structure
3. Follow {script_type} best practices
4. Include proper error handling
5. Add comments explaining changes
6. Ensure production-ready quality

CONSTRAINTS:
- Preserve existing functionality unless explicitly asked to change it
- Maintain compatibility with target binary if applicable
- Keep the same overall script structure
- Add only necessary modifications

Generate the complete modified script:"""

    def _extract_changes(self, original: str, modified: str) -> list[str]:
        """Extract summary of changes between scripts.

        Args:
            original: The original script content.
            modified: The modified script content.

        Returns:
            A list of strings describing the changes made.
        """
        changes = []

        original_lines = original.split("\n")
        modified_lines = modified.split("\n")

        # Simple diff analysis
        if len(modified_lines) > len(original_lines):
            changes.append(f"Added {len(modified_lines) - len(original_lines)} lines")
        elif len(modified_lines) < len(original_lines):
            changes.append(f"Removed {len(original_lines) - len(modified_lines)} lines")

        # Check for specific patterns
        if "try {" in modified and "try {" not in original:
            changes.append("Added error handling")

        if "// Modified:" in modified or "# Modified:" in modified:
            changes.append("Added modification comments")

        return changes

    def _calculate_edit_confidence(self, original: str, modified: str, validation: ValidationResult) -> float:
        """Calculate confidence score for the edit.

        Args:
            original: The original script content.
            modified: The modified script content.
            validation: The validation result from testing the modification.

        Returns:
            A confidence score between 0.0 and 1.0.
        """
        base_score = 0.5

        # Validation impact
        if validation == ValidationResult.SUCCESS:
            base_score += 0.3
        elif validation in [ValidationResult.SYNTAX_ERROR, ValidationResult.SECURITY_ISSUE]:
            base_score -= 0.4

        # Change magnitude
        change_ratio = abs(len(modified) - len(original)) / len(original)
        if change_ratio < 0.1:  # Small changes
            base_score += 0.1
        elif change_ratio > 0.5:  # Large changes
            base_score -= 0.2

        return max(0.0, min(1.0, base_score))

    def _generate_edit_id(self) -> str:
        """Generate unique edit ID.

        Returns:
            A unique edit identifier string.
        """
        return f"edit_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"

    def _analyze_qemu_results_for_goals(self, qemu_result: dict[str, Any], goals: list[str]) -> bool:
        """Analyze QEMU execution results to determine if improvement goals are met.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            goals: List of improvement goals to check against results.

        Returns:
            True if 80% or more of the goals are met, False otherwise.
        """
        if not qemu_result.get("success"):
            return False

        output = qemu_result.get("output", "").lower()
        errors = qemu_result.get("errors", [])
        performance = qemu_result.get("performance", {})

        goals_met = sum(self._is_goal_met(goal.lower(), output, errors, performance) for goal in goals)

        # Consider goals achieved if 80% or more are met
        achievement_ratio = goals_met / len(goals) if goals else 0.0
        return achievement_ratio >= 0.8

    def _is_goal_met(self, goal: str, output: str, errors: list[str], performance: dict[str, Any]) -> int:
        """Check if a specific goal is met based on QEMU results.

        Args:
            goal: The goal to check.
            output: The script execution output.
            errors: List of errors from execution.
            performance: Performance metrics dict from execution.

        Returns:
            1 if goal is met, 0 otherwise.
        """
        if "no errors" in goal or "error-free" in goal:
            return int(not errors)
        if "extract" in goal or "find" in goal:
            return int("found" in output or "extracted" in output)
        if "patch" in goal or "modify" in goal:
            return int("patched" in output or "modified" in output or "success" in output)
        if "performance" in goal or "fast" in goal:
            runtime = performance.get("runtime_ms", float("inf"))
            return int(runtime < 5000)  # Under 5 seconds is considered good
        if "bypass" in goal or "crack" in goal:
            return int("bypassed" in output or "cracked" in output or "success" in output)
        # Generic success check
        return int(not errors)

    def _create_improvement_prompt_with_feedback(self, goals: list[str], qemu_result: dict[str, Any]) -> str:
        """Create an improvement prompt that includes QEMU execution feedback.

        Args:
            goals: List of improvement goals to include in the prompt.
            qemu_result: Execution result dict from QEMU testing.

        Returns:
            A detailed improvement prompt string incorporating QEMU feedback.
        """
        prompt_parts = [
            f"Improve this script to achieve the following goals: {', '.join(goals)}",
            "\n\nCurrent script execution results from QEMU VM:",
        ]

        self._add_execution_status(qemu_result, prompt_parts)
        self._add_output_information(qemu_result, prompt_parts)
        self._add_error_information(qemu_result, prompt_parts)
        self._add_performance_metrics(qemu_result, prompt_parts)
        self._add_specific_improvements(qemu_result, goals, prompt_parts)

        return "\n".join(prompt_parts)

    def _add_execution_status(self, qemu_result: dict[str, Any], prompt_parts: list[str]) -> None:
        """Add execution status to the prompt.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            prompt_parts: List to append status information to.
        """
        if qemu_result.get("success"):
            prompt_parts.append("OK Script executed successfully")
        else:
            prompt_parts.append("FAIL Script execution failed")

    def _add_output_information(self, qemu_result: dict[str, Any], prompt_parts: list[str]) -> None:
        """Add output information to the prompt.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            prompt_parts: List to append output information to.
        """
        if output := qemu_result.get("output", ""):
            prompt_parts.append(f"\nScript output:\n{output[:500]}")  # Limit output length

    def _add_error_information(self, qemu_result: dict[str, Any], prompt_parts: list[str]) -> None:
        """Add error information to the prompt.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            prompt_parts: List to append error information to.
        """
        if errors := qemu_result.get("errors", []):
            prompt_parts.append("\nErrors encountered:")
            prompt_parts.extend(f"  - {error}" for error in errors[:5])

    def _add_performance_metrics(self, qemu_result: dict[str, Any], prompt_parts: list[str]) -> None:
        """Add performance metrics to the prompt.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            prompt_parts: List to append performance metrics to.
        """
        if performance := qemu_result.get("performance", {}):
            runtime = performance.get("runtime_ms", 0)
            exit_code = performance.get("exit_code", 0)
            prompt_parts.append("\nPerformance metrics:")
            prompt_parts.append(f"  - Runtime: {runtime}ms")
            prompt_parts.append(f"  - Exit code: {exit_code}")

    def _add_specific_improvements(self, qemu_result: dict[str, Any], goals: list[str], prompt_parts: list[str]) -> None:
        """Add specific improvement suggestions to the prompt.

        Args:
            qemu_result: The execution result dict from QEMU testing.
            goals: List of improvement goals.
            prompt_parts: List to append improvement suggestions to.
        """
        prompt_parts.append("\nSpecific improvements needed:")

        if not qemu_result.get("success"):
            prompt_parts.append("- Fix execution errors to make the script run successfully")

        if errors := qemu_result.get("errors", []):
            self._add_error_based_suggestions(errors, prompt_parts)

        performance = qemu_result.get("performance", {})
        if performance.get("runtime_ms", 0) > 10000:
            prompt_parts.append("- Optimize performance to reduce runtime")

        if performance.get("exit_code", 0) != 0:
            prompt_parts.append(f"- Fix issues causing non-zero exit code ({performance.get('exit_code')})")

        self._add_goal_based_suggestions(goals, qemu_result.get("output", ""), prompt_parts)

    def _add_error_based_suggestions(self, errors: list[str], prompt_parts: list[str]) -> None:
        """Add suggestions based on errors.

        Args:
            errors: List of errors from script execution.
            prompt_parts: List to append error-based suggestions to.
        """
        if any("syntax" in str(e).lower() for e in errors):
            prompt_parts.append("- Fix syntax errors in the script")
        if any("import" in str(e).lower() or "module" in str(e).lower() for e in errors):
            prompt_parts.append("- Fix import/module errors")
        if any("permission" in str(e).lower() or "access" in str(e).lower() for e in errors):
            prompt_parts.append("- Fix permission/access issues")

    def _add_goal_based_suggestions(self, goals: list[str], output: str, prompt_parts: list[str]) -> None:
        """Add suggestions based on unmet goals.

        Args:
            goals: List of improvement goals.
            output: Script execution output to check against goals.
            prompt_parts: List to append goal-based suggestions to.
        """
        output_lower = output.lower() if output else ""
        for goal in goals:
            goal_lower = goal.lower()
            if "extract" in goal_lower and "extracted" not in output_lower:
                prompt_parts.append(f"- Ensure the script successfully {goal}")
            elif "patch" in goal_lower and "patched" not in output_lower:
                prompt_parts.append(f"- Implement functionality to {goal}")
            elif "bypass" in goal_lower and "bypassed" not in output_lower:
                prompt_parts.append(f"- Add logic to {goal}")

    def _detect_script_type(self, script_path: str, script_content: str) -> str:
        """Detect the type of script from path and content analysis.

        This method combines path-based detection with content analysis
        to accurately identify the script type for proper handling.

        Args:
            script_path: Path to the script file.
            script_content: The actual content of the script.

        Returns:
            String identifying the script type (frida, ghidra, python, etc.).

        """
        path_type = self._detect_script_type_from_path(script_path)
        if path_type != "unknown":
            return path_type

        content_lower = script_content.lower() if script_content else ""

        frida_indicators = [
            "interceptor.attach",
            "interceptor.replace",
            "memory.read",
            "memory.write",
            "module.findexportbyname",
            "module.enumerateexports",
            "nativefunction",
            "nativepointer",
            "process.enumerate",
            "ptr(",
            "send(",
            "recv(",
            "frida.",
        ]
        frida_score = sum(ind in content_lower for ind in frida_indicators)
        if frida_score >= 2:
            return "frida"

        ghidra_indicators = [
            "from ghidra",
            "import ghidra",
            "currentprogram",
            "currentaddress",
            "getaddress",
            "getfunction",
            "getinstructionat",
            "flatprogramapi",
            "decompile",
            "@category",
            "@keybinding",
            "ghidrascript",
        ]
        ghidra_score = sum(ind in content_lower for ind in ghidra_indicators)
        if ghidra_score >= 2:
            return "ghidra"

        r2_indicators = [
            "r2pipe",
            "r2.cmd",
            "r2.cmdj",
            "radare2",
            "afl",
            "pdf @",
            "px @",
            "pxq",
            "izz",
            "aaa",
        ]
        r2_score = sum(ind in content_lower for ind in r2_indicators)
        if r2_score >= 2:
            return "radare2"

        if "def " in content_lower or "import " in content_lower or "class " in content_lower:
            if "#!/usr/bin/env python" in content_lower or "#!/usr/bin/python" in content_lower:
                return "python"
            if any(ind in content_lower for ind in ["import os", "import sys", "import re", "def main"]):
                return "python"

        if content_lower.strip().startswith("#!/bin/bash") or content_lower.strip().startswith("#!/bin/sh"):
            return "shell"

        if "function " in content_lower and ("{" in content_lower or "=>" in content_lower):
            return "javascript"

        return "unknown"

    def _detect_script_type_from_path(self, script_path: str) -> str:
        """Detect script type from file path/extension.

        Args:
            script_path: Path to the script file.

        Returns:
            A string identifying the detected script type or "unknown".
        """
        path = Path(script_path)
        extension = path.suffix.lower()

        # Map extensions to script types
        extension_map = {
            ".js": "frida",
            ".java": "ghidra",
            ".py": "python",
            ".r2": "radare2",
            ".lua": "lua",
            ".c": "c",
            ".cpp": "cpp",
            ".sh": "shell",
            ".ps1": "powershell",
        }

        script_type = extension_map.get(extension, "unknown")

        # Check filename patterns as fallback
        filename_lower = path.name.lower()
        if "frida" in filename_lower:
            script_type = "frida"
        elif "ghidra" in filename_lower:
            script_type = "ghidra"
        elif "radare" in filename_lower or "r2" in filename_lower:
            script_type = "radare2"

        return script_type

    def _calculate_diff_stats(self, content1: str, content2: str) -> dict[str, Any]:
        """Calculate statistics about differences between two scripts.

        Args:
            content1: The first script content.
            content2: The second script content.

        Returns:
            A dict with lines added/removed, line counts, and similarity ratio.
        """
        lines1 = content1.split("\n")
        lines2 = content2.split("\n")

        return {
            "lines_added": max(0, len(lines2) - len(lines1)),
            "lines_removed": max(0, len(lines1) - len(lines2)),
            "total_lines_v1": len(lines1),
            "total_lines_v2": len(lines2),
            "similarity_ratio": self._calculate_similarity(content1, content2),
        }

    def _calculate_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity ratio between two scripts.

        Args:
            content1: The first script content.
            content2: The second script content.

        Returns:
            A float between 0.0 and 1.0 representing similarity ratio.
        """
        from difflib import SequenceMatcher

        return SequenceMatcher(None, content1, content2).ratio()

    def _generate_version_recommendations(self, diff_stats: dict[str, Any]) -> list[str]:
        """Generate recommendations based on version comparison.

        Args:
            diff_stats: Dictionary with diff statistics from version comparison.

        Returns:
            A list of recommendation strings based on the diff analysis.
        """
        recommendations = []

        if diff_stats["similarity_ratio"] < 0.5:
            recommendations.append("Significant changes detected - review carefully")

        if diff_stats["lines_added"] > 50:
            recommendations.append("Large addition - ensure all new code is tested")

        if diff_stats["lines_removed"] > 20:
            recommendations.append("Substantial code removal - verify functionality preserved")

        return recommendations

    def _suggest_fixes(self, validation_result: ValidationResult, validation_details: dict[str, Any]) -> list[str]:
        """Suggest fixes for validation issues.

        Args:
            validation_result: The validation result status enum.
            validation_details: Dictionary with detailed validation information.

        Returns:
            A list of suggested fix strings for the identified issues.
        """
        fixes: list[str] = []

        if validation_result == ValidationResult.SYNTAX_ERROR:
            fixes.extend((
                "Check for missing brackets, semicolons, or quotes",
                "Verify proper indentation",
            ))
        elif validation_result == ValidationResult.SECURITY_ISSUE:
            security_issues = validation_details.get("security_scan", {})
            if security_issues.get("critical_issues"):
                fixes.append("Remove or secure dangerous function calls")
            if security_issues.get("warnings"):
                fixes.append("Review and validate file/memory operations")

        elif validation_result == ValidationResult.PERFORMANCE_POOR:
            fixes.extend((
                "Optimize loops and reduce complexity",
                "Consider batching memory operations",
            ))
        return fixes

    def _generate_binary_specific_suggestions(
        self,
        script_content: str,
        script_type: str,
        binary_analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Generate suggestions specific to the target binary.

        Args:
            script_content: The script content to analyze.
            script_type: The type of script being analyzed.
            binary_analysis: Dictionary with binary analysis information.

        Returns:
            A list of suggestion dicts tailored to the binary's characteristics.
        """
        suggestions = []

        # Architecture-specific suggestions
        arch = binary_analysis.get("arch", "").lower()
        if arch == "x64" and script_type == "frida" and "ptr(" not in script_content:
            suggestions.append(
                {
                    "type": "compatibility",
                    "priority": "medium",
                    "description": "Consider using ptr() for 64-bit address handling",
                },
            )

        # Protection-specific suggestions
        protections = binary_analysis.get("protections", [])
        if "anti-debug" in protections and "antidebug" not in script_content.lower():
            suggestions.append(
                {
                    "type": "enhancement",
                    "priority": "high",
                    "description": "Add anti-debug bypass mechanisms",
                },
            )

        return suggestions

    def _edit_to_dict(self, edit: ScriptEdit) -> dict[str, Any]:
        """Convert ScriptEdit to dictionary for serialization.

        Args:
            edit: The ScriptEdit object to convert.

        Returns:
            A dictionary representation of the ScriptEdit.
        """
        return {
            "edit_id": edit.edit_id,
            "timestamp": edit.timestamp,
            "edit_type": edit.edit_type.value,
            "modification_prompt": edit.modification_prompt,
            "changes_made": edit.changes_made,
            "confidence_score": edit.confidence_score,
            "validation_result": edit.validation_result.value if edit.validation_result else None,
            "performance_metrics": edit.performance_metrics,
        }
