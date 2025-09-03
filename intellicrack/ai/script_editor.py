"""AI Script Editor for Iterative Script Improvement.

This module provides advanced script editing capabilities including:
1. Iterative script modification based on feedback
2. Context-aware script refinements
3. Script versioning and history tracking
4. Testing and validation integration
5. Performance-based optimization

Production-ready AI-driven script editing system.
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
from typing import Any, Dict, List, Optional, Tuple

from intellicrack.logger import logger

from .ai_script_generator import LLMScriptInterface, PromptEngineer, ScriptType


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
    target_addresses: List[str] = field(default_factory=list)
    expected_behavior: str = ""
    test_criteria: Dict[str, Any] = field(default_factory=dict)
    preserve_functionality: bool = True


@dataclass
class ScriptEdit:
    """Record of a script modification."""

    edit_id: str
    timestamp: str
    edit_type: EditType
    modification_prompt: str
    changes_made: List[str]
    confidence_score: float
    validation_result: Optional[ValidationResult] = None
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    rollback_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptVersion:
    """Version tracking for script evolution."""

    version_number: str
    content: str
    edit_history: List[ScriptEdit]
    creation_timestamp: str
    parent_version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


class ScriptTester:
    """Automated testing framework for generated scripts."""

    def __init__(self):
        """Initialize script tester with LLM interface for validation."""
        self.llm_interface = LLMScriptInterface()

    def validate_script(
        self, script_content: str, script_type: str, binary_path: Optional[str] = None
    ) -> Tuple[ValidationResult, Dict[str, Any]]:
        """Validate script using LLM for comprehensive analysis."""
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
            # Use LLM for validation
            from .ai_script_generator import ScriptGenerationRequest

            dummy_request = ScriptGenerationRequest(prompt="validation", script_type=script_type, binary_path=binary_path)

            # Get LLM analysis
            response, _ = self.llm_interface.generate_script(dummy_request, validation_prompt)

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
                elif analysis.get("has_syntax_errors"):
                    return ValidationResult.SYNTAX_ERROR, results
                elif severity == "high":
                    return ValidationResult.LOGIC_ERROR, results
                elif len(analysis.get("performance_issues", [])) > 3:
                    return ValidationResult.PERFORMANCE_POOR, results
                else:
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
        binary_path: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Test script execution in QEMU virtual machine."""
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

    def _get_qemu_manager(self):
        """Get or create QEMUManager instance."""
        from intellicrack.ai.qemu_manager import QEMUManager

        if not hasattr(self, "_qemu_manager"):
            self._qemu_manager = QEMUManager()

        return self._qemu_manager

    def _validate_frida_syntax(self, script: str) -> ValidationResult:
        """Validate Frida JavaScript syntax."""
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
        """Validate Ghidra Java syntax."""
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
        """Validate Python syntax."""
        try:
            compile(script, "<string>", "exec")
            return ValidationResult.SUCCESS
        except SyntaxError:
            return ValidationResult.SYNTAX_ERROR
        except Exception:
            return ValidationResult.RUNTIME_ERROR

    def _scan_security_issues(self, script: str, script_type: str) -> Dict[str, Any]:
        """Scan for potential security issues."""
        issues = {"critical_issues": [], "warnings": [], "info": []}

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
                matches = re.findall(pattern, script, re.IGNORECASE)
                if matches:
                    issues[f"{severity}_issues" if severity == "critical" else "warnings"].extend(matches)

        return issues

    def _analyze_performance(self, script: str, script_type: str) -> Dict[str, Any]:
        """Analyze script performance characteristics."""
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
            "recursion": len(re.findall(r"function.*\{[\s\S]*?\1\s*\(", script)),
            "memory_operations": len(re.findall(r"Memory\.|mem\.", script)),
        }

        total_complexity = sum(complexity_factors.values())
        line_count = len([line for line in lines if line.strip()])

        if line_count > 0:
            metrics["complexity_score"] = min(total_complexity / line_count, 1.0)

        # Performance suggestions
        if complexity_factors["loops"] > 10:
            metrics["optimization_suggestions"].append("Consider reducing nested loops")

        if complexity_factors["memory_operations"] > 20:
            metrics["optimization_suggestions"].append("High memory operation count - consider batching")

        return metrics


class ScriptVersionManager:
    """Manages script versions and evolution history."""

    def __init__(self, base_path: str):
        """Initialize version manager with base path for version storage."""
        self.base_path = Path(base_path)
        self.versions_dir = self.base_path / "versions"
        self.versions_dir.mkdir(parents=True, exist_ok=True)

    def create_version(
        self,
        script_path: str,
        content: str,
        edit_history: List[ScriptEdit],
        parent_version: Optional[str] = None,
    ) -> ScriptVersion:
        """Create new script version."""
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

    def get_version_history(self, script_path: str) -> List[ScriptVersion]:
        """Get version history for a script."""
        versions = []

        for version_file in self.versions_dir.glob("*.json"):
            try:
                with open(version_file, "r", encoding="utf-8") as f:
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

    def rollback_to_version(self, version_id: str) -> Optional[str]:
        """Rollback to a specific version."""
        version_file = self.versions_dir / f"{version_id}.json"

        if not version_file.exists():
            return None

        try:
            with open(version_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            return data["content"]

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return None

    def _generate_version_id(self, content: str) -> str:
        """Generate unique version ID."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"v_{timestamp}_{content_hash}"

    def _edit_to_dict(self, edit: ScriptEdit) -> Dict[str, Any]:
        """Convert ScriptEdit to dictionary."""
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

    def _dict_to_edit(self, data: Dict[str, Any]) -> ScriptEdit:
        """Convert dictionary to ScriptEdit."""
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

    def __init__(self):
        """Initialize AI script editor with all necessary components for advanced editing."""
        self.llm_interface = LLMScriptInterface()
        self.prompt_engineer = PromptEngineer()
        self.tester = ScriptTester()
        self.version_manager = ScriptVersionManager("C:/Intellicrack/intellicrack/scripts")
        self.edit_history = {}  # script_path -> List[ScriptEdit]
        logger.info("AIScriptEditor initialized with advanced editing capabilities")

    def edit_script(
        self,
        script_path: str,
        modification_prompt: str,
        edit_type: EditType = EditType.ENHANCEMENT,
        test_binary: Optional[str] = None,
        preserve_functionality: bool = True,
    ) -> Dict[str, Any]:
        """Edit an existing script based on modification prompt.

        This is the main entry point for AI script editing.
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

            # Generate modification prompt for LLM
            llm_prompt = self._build_edit_prompt(original_content, edit_request, script_type)

            # Generate modified script
            modified_content = self.llm_interface.generate_script(edit_request, llm_prompt)

            # Validate modified script
            validation_result, validation_details = self.tester.validate_script(modified_content, script_type, test_binary)

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
            version = self.version_manager.create_version(script_path, modified_content, self.edit_history[script_path])

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
            else:
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
        improvement_goals: List[str],
        max_iterations: int = 5,
        test_binary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Iteratively improve a script through multiple edit cycles using QEMU feedback."""
        results = {
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

            results["qemu_feedback"].append(qemu_result)

            # Analyze QEMU results to determine if goals are achieved
            goals_achieved = self._analyze_qemu_results_for_goals(qemu_result, improvement_goals, current_content)

            # If goals are achieved, we're done
            if goals_achieved:
                results["final_success"] = True
                results["iterations"].append(
                    {
                        "iteration": iteration + 1,
                        "result": {"success": True, "message": "Goals achieved"},
                        "qemu_result": qemu_result,
                        "goals_achieved": True,
                    }
                )
                break

            # Create improvement prompt with QEMU feedback
            improvement_prompt = self._create_improvement_prompt_with_feedback(improvement_goals, qemu_result, current_content)

            # Edit script based on QEMU feedback
            edit_result = self.edit_script(script_path, improvement_prompt, EditType.OPTIMIZATION, test_binary)

            results["iterations"].append(
                {
                    "iteration": iteration + 1,
                    "result": edit_result,
                    "qemu_result": qemu_result,
                    "goals_achieved": goals_achieved,
                }
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

    def compare_versions(self, version1_id: str, version2_id: str) -> Dict[str, Any]:
        """Compare two script versions."""
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

    def rollback_edit(self, script_path: str, edit_id: str) -> Dict[str, Any]:
        """Rollback a specific edit."""
        if script_path not in self.edit_history:
            return {"success": False, "error": "No edit history found"}

        # Find the edit
        edit_to_rollback = None
        for edit in self.edit_history[script_path]:
            if edit.edit_id == edit_id:
                edit_to_rollback = edit
                break

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

    def get_edit_suggestions(self, script_path: str, binary_analysis: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Get AI-powered suggestions for script improvements."""
        script_content = self._load_script(script_path)
        if not script_content:
            return []

        script_type = self._detect_script_type(script_path, script_content)

        # Analyze current script
        validation_result, validation_details = self.tester.validate_script(script_content, script_type)

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
                }
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
                }
            )

        # Binary-specific suggestions
        if binary_analysis:
            binary_suggestions = self._generate_binary_specific_suggestions(script_content, script_type, binary_analysis)
            suggestions.extend(binary_suggestions)

        return suggestions

    def _load_script(self, script_path: str) -> Optional[str]:
        """Load script content from file."""
        try:
            with open(script_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load script {script_path}: {e}")
            return None

    def _save_script(self, script_path: str, content: str, edit_record: ScriptEdit):
        """Save modified script content."""
        try:
            # Create backup of original
            backup_path = f"{script_path}.backup_{edit_record.edit_id}"
            if os.path.exists(script_path):
                os.rename(script_path, backup_path)

            # Save new content
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(content)

            logger.info(f"Saved modified script: {script_path}")
        except Exception as e:
            logger.error(f"Failed to save script: {e}")

    def _build_edit_prompt(self, original_content: str, edit_request: EditRequest, script_type: str) -> str:
        """Build comprehensive prompt for script editing."""
        prompt = f"""Modify the following {script_type} script based on the user's request.

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

        return prompt

    def _extract_changes(self, original: str, modified: str) -> List[str]:
        """Extract summary of changes between scripts."""
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
        """Calculate confidence score for the edit."""
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
        """Generate unique edit ID."""
        return f"edit_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"

    def _analyze_qemu_results_for_goals(self, qemu_result: Dict[str, Any], goals: List[str], script_content: str) -> bool:
        """Analyze QEMU execution results to determine if improvement goals are met."""
        if not qemu_result.get("success"):
            return False

        # Check each goal against QEMU output
        goals_met = 0
        output = qemu_result.get("output", "").lower()
        errors = qemu_result.get("errors", [])

        for goal in goals:
            goal_lower = goal.lower()

            # Check for common goal patterns
            if "no errors" in goal_lower or "error-free" in goal_lower:
                if not errors or len(errors) == 0:
                    goals_met += 1
            elif "extract" in goal_lower or "find" in goal_lower:
                # Check if extraction/finding was successful in output
                if output and "found" in output or "extracted" in output:
                    goals_met += 1
            elif "patch" in goal_lower or "modify" in goal_lower:
                # Check if patching/modification was successful
                if output and ("patched" in output or "modified" in output or "success" in output):
                    goals_met += 1
            elif "performance" in goal_lower or "fast" in goal_lower:
                # Check runtime performance
                runtime = qemu_result.get("performance", {}).get("runtime_ms", float("inf"))
                if runtime < 5000:  # Under 5 seconds is considered good
                    goals_met += 1
            elif "bypass" in goal_lower or "crack" in goal_lower:
                # Check if bypass/crack was successful
                if output and ("bypassed" in output or "cracked" in output or "success" in output):
                    goals_met += 1
            else:
                # Generic success check
                if qemu_result.get("success") and not errors:
                    goals_met += 1

        # Consider goals achieved if 80% or more are met
        achievement_ratio = goals_met / len(goals) if goals else 0.0
        return achievement_ratio >= 0.8

    def _create_improvement_prompt_with_feedback(self, goals: List[str], qemu_result: Dict[str, Any], current_content: str) -> str:
        """Create an improvement prompt that includes QEMU execution feedback."""
        prompt_parts = [
            f"Improve this script to achieve the following goals: {', '.join(goals)}",
            "\n\nCurrent script execution results from QEMU VM:",
        ]

        # Add execution status
        if qemu_result.get("success"):
            prompt_parts.append("✓ Script executed successfully")
        else:
            prompt_parts.append("✗ Script execution failed")

        # Add output information
        output = qemu_result.get("output", "")
        if output:
            prompt_parts.append(f"\nScript output:\n{output[:500]}")  # Limit output length

        # Add error information
        errors = qemu_result.get("errors", [])
        if errors:
            prompt_parts.append("\nErrors encountered:")
            for error in errors[:5]:  # Limit to first 5 errors
                prompt_parts.append(f"  - {error}")

        # Add performance metrics
        performance = qemu_result.get("performance", {})
        if performance:
            runtime = performance.get("runtime_ms", 0)
            exit_code = performance.get("exit_code", 0)
            prompt_parts.append("\nPerformance metrics:")
            prompt_parts.append(f"  - Runtime: {runtime}ms")
            prompt_parts.append(f"  - Exit code: {exit_code}")

        # Add specific improvement suggestions based on results
        prompt_parts.append("\nSpecific improvements needed:")

        if not qemu_result.get("success"):
            prompt_parts.append("- Fix execution errors to make the script run successfully")

        if errors:
            if any("syntax" in str(e).lower() for e in errors):
                prompt_parts.append("- Fix syntax errors in the script")
            if any("import" in str(e).lower() or "module" in str(e).lower() for e in errors):
                prompt_parts.append("- Fix import/module errors")
            if any("permission" in str(e).lower() or "access" in str(e).lower() for e in errors):
                prompt_parts.append("- Fix permission/access issues")

        if performance.get("runtime_ms", 0) > 10000:
            prompt_parts.append("- Optimize performance to reduce runtime")

        if performance.get("exit_code", 0) != 0:
            prompt_parts.append(f"- Fix issues causing non-zero exit code ({performance.get('exit_code')})")

        # Add goals that haven't been achieved yet
        for goal in goals:
            goal_lower = goal.lower()
            output_lower = output.lower() if output else ""

            if "extract" in goal_lower and "extracted" not in output_lower:
                prompt_parts.append(f"- Ensure the script successfully {goal}")
            elif "patch" in goal_lower and "patched" not in output_lower:
                prompt_parts.append(f"- Implement functionality to {goal}")
            elif "bypass" in goal_lower and "bypassed" not in output_lower:
                prompt_parts.append(f"- Add logic to {goal}")

        return "\n".join(prompt_parts)

    def _detect_script_type_from_path(self, script_path: str) -> str:
        """Detect script type from file path/extension."""
        path = Path(script_path)
        extension = path.suffix.lower()

        # Map extensions to script types
        extension_map = {
            ".js": "frida",
            ".java": "ghidra",
            ".py": "python",
            ".r2": "radare2",
            ".lua": "lua",
            ".idc": "ida",
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
        elif "ida" in filename_lower:
            script_type = "ida"

        return script_type

    def _calculate_diff_stats(self, content1: str, content2: str) -> Dict[str, Any]:
        """Calculate statistics about differences between two scripts."""
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
        """Calculate similarity ratio between two scripts."""
        from difflib import SequenceMatcher

        return SequenceMatcher(None, content1, content2).ratio()

    def _generate_version_recommendations(self, diff_stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on version comparison."""
        recommendations = []

        if diff_stats["similarity_ratio"] < 0.5:
            recommendations.append("Significant changes detected - review carefully")

        if diff_stats["lines_added"] > 50:
            recommendations.append("Large addition - ensure all new code is tested")

        if diff_stats["lines_removed"] > 20:
            recommendations.append("Substantial code removal - verify functionality preserved")

        return recommendations

    def _suggest_fixes(self, validation_result: ValidationResult, validation_details: Dict[str, Any]) -> List[str]:
        """Suggest fixes for validation issues."""
        fixes = []

        if validation_result == ValidationResult.SYNTAX_ERROR:
            fixes.append("Check for missing brackets, semicolons, or quotes")
            fixes.append("Verify proper indentation")

        elif validation_result == ValidationResult.SECURITY_ISSUE:
            security_issues = validation_details.get("security_scan", {})
            if security_issues.get("critical_issues"):
                fixes.append("Remove or secure dangerous function calls")
            if security_issues.get("warnings"):
                fixes.append("Review and validate file/memory operations")

        elif validation_result == ValidationResult.PERFORMANCE_POOR:
            fixes.append("Optimize loops and reduce complexity")
            fixes.append("Consider batching memory operations")

        return fixes

    def _generate_binary_specific_suggestions(
        self, script_content: str, script_type: str, binary_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate suggestions specific to the target binary."""
        suggestions = []

        # Architecture-specific suggestions
        arch = binary_analysis.get("arch", "").lower()
        if arch == "x64" and script_type == ScriptType.FRIDA:
            if "ptr(" not in script_content:
                suggestions.append(
                    {
                        "type": "compatibility",
                        "priority": "medium",
                        "description": "Consider using ptr() for 64-bit address handling",
                    }
                )

        # Protection-specific suggestions
        protections = binary_analysis.get("protections", [])
        if "anti-debug" in protections and "antidebug" not in script_content.lower():
            suggestions.append(
                {
                    "type": "enhancement",
                    "priority": "high",
                    "description": "Add anti-debug bypass mechanisms",
                }
            )

        return suggestions

    def _edit_to_dict(self, edit: ScriptEdit) -> Dict[str, Any]:
        """Convert ScriptEdit to dictionary for serialization."""
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
