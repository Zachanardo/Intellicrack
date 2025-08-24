"""Radare2 Advanced Binary Comparison and Diffing Engine.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import logging
from difflib import SequenceMatcher
from typing import Any

from ...utils.tools.radare2_utils import R2Exception, r2_session

logger = logging.getLogger(__name__)


class R2BinaryDiff:
    """Advanced binary comparison and diffing engine using radare2.

    Provides comprehensive binary analysis including:
    - Function-level comparison
    - Instruction-level diffing
    - String comparison and analysis
    - Import/export differences
    - Structural changes detection
    - Patch detection and analysis
    - Version comparison
    - Security enhancement detection
    """

    def __init__(self, binary1_path: str, binary2_path: str, radare2_path: str | None = None):
        """Initialize binary diff analyzer."""
        self.binary1_path = binary1_path
        self.binary2_path = binary2_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)

    def analyze_differences(self) -> dict[str, Any]:
        """Perform comprehensive binary difference analysis."""
        result = {
            "binary1": self.binary1_path,
            "binary2": self.binary2_path,
            "metadata_diff": {},
            "function_diff": {},
            "instruction_diff": {},
            "string_diff": {},
            "import_export_diff": {},
            "section_diff": {},
            "entry_point_diff": {},
            "security_diff": {},
            "patch_analysis": {},
            "similarity_metrics": {},
            "change_summary": {},
            "vulnerability_impact": {},
        }

        try:
            with r2_session(self.binary1_path, self.radare2_path) as r2_1:
                with r2_session(self.binary2_path, self.radare2_path) as r2_2:
                    # Basic metadata comparison
                    result["metadata_diff"] = self._compare_metadata(r2_1, r2_2)

                    # Function-level comparison
                    result["function_diff"] = self._compare_functions(r2_1, r2_2)

                    # Instruction-level comparison
                    result["instruction_diff"] = self._compare_instructions(r2_1, r2_2)

                    # String comparison
                    result["string_diff"] = self._compare_strings(r2_1, r2_2)

                    # Import/export comparison
                    result["import_export_diff"] = self._compare_imports_exports(r2_1, r2_2)

                    # Section comparison
                    result["section_diff"] = self._compare_sections(r2_1, r2_2)

                    # Entry point comparison
                    result["entry_point_diff"] = self._compare_entry_points(r2_1, r2_2)

                    # Security features comparison
                    result["security_diff"] = self._compare_security_features(r2_1, r2_2)

                    # Patch analysis
                    result["patch_analysis"] = self._analyze_patches(r2_1, r2_2)

                    # Calculate similarity metrics
                    result["similarity_metrics"] = self._calculate_similarity_metrics(result)

                    # Generate change summary
                    result["change_summary"] = self._generate_change_summary(result)

                    # Assess vulnerability impact
                    result["vulnerability_impact"] = self._assess_vulnerability_impact(result)

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Binary diff analysis failed: {e}")

        return result

    def _compare_metadata(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare basic binary metadata."""
        try:
            info1 = r2_1.get_info()
            info2 = r2_2.get_info()

            bin1 = info1.get("bin", {})
            bin2 = info2.get("bin", {})

            return {
                "file_size_diff": bin2.get("size", 0) - bin1.get("size", 0),
                "architecture_change": bin1.get("arch") != bin2.get("arch"),
                "bits_change": bin1.get("bits") != bin2.get("bits"),
                "endian_change": bin1.get("endian") != bin2.get("endian"),
                "compiler_change": bin1.get("compiler") != bin2.get("compiler"),
                "stripped_change": bin1.get("stripped") != bin2.get("stripped"),
                "checksum_diff": {
                    "binary1": self._calculate_file_hash(self.binary1_path),
                    "binary2": self._calculate_file_hash(self.binary2_path),
                },
                "build_info": {
                    "binary1": {
                        "compiler": bin1.get("compiler", "unknown"),
                        "build_id": bin1.get("buildid", ""),
                        "debug_info": bin1.get("dbg_file", ""),
                    },
                    "binary2": {
                        "compiler": bin2.get("compiler", "unknown"),
                        "build_id": bin2.get("buildid", ""),
                        "debug_info": bin2.get("dbg_file", ""),
                    },
                },
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare metadata"}

    def _compare_functions(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare functions between binaries."""
        try:
            functions1 = {f["name"]: f for f in r2_1.get_functions()}
            functions2 = {f["name"]: f for f in r2_2.get_functions()}

            # Find added, removed, and modified functions
            names1 = set(functions1.keys())
            names2 = set(functions2.keys())

            added_functions = names2 - names1
            removed_functions = names1 - names2
            common_functions = names1 & names2

            modified_functions = []
            unchanged_functions = []

            for name in common_functions:
                func1 = functions1[name]
                func2 = functions2[name]

                # Compare function properties
                if (
                    func1.get("size") != func2.get("size")
                    or func1.get("cc") != func2.get("cc")
                    or func1.get("offset") != func2.get("offset")
                ):
                    # Detailed function comparison
                    detailed_diff = self._compare_function_details(r2_1, r2_2, func1, func2)
                    modified_functions.append(
                        {
                            "name": name,
                            "changes": detailed_diff,
                        }
                    )
                else:
                    unchanged_functions.append(name)

            return {
                "total_functions": {
                    "binary1": len(functions1),
                    "binary2": len(functions2),
                },
                "added_functions": list(added_functions),
                "removed_functions": list(removed_functions),
                "modified_functions": modified_functions,
                "unchanged_functions": unchanged_functions,
                "function_similarity": len(unchanged_functions) / max(1, len(common_functions)),
                "major_changes": len(modified_functions) > len(common_functions) * 0.3,
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare functions"}

    def _compare_function_details(
        self, r2_1, r2_2, func1: dict[str, Any], func2: dict[str, Any]
    ) -> dict[str, Any]:
        """Compare detailed function properties."""
        changes = {
            "size_change": func2.get("size", 0) - func1.get("size", 0),
            "address_change": func2.get("offset", 0) - func1.get("offset", 0),
            "complexity_change": func2.get("cc", 0) - func1.get("cc", 0),
            "instruction_changes": [],
        }

        try:
            # Get function disassembly for both
            addr1 = func1.get("offset", 0)
            addr2 = func2.get("offset", 0)

            if addr1 and addr2:
                disasm1 = r2_1._execute_command(f"pdf @ {hex(addr1)}")
                disasm2 = r2_2._execute_command(f"pdf @ {hex(addr2)}")

                # Compare instruction sequences
                instructions1 = self._extract_instructions(disasm1)
                instructions2 = self._extract_instructions(disasm2)

                changes["instruction_changes"] = self._diff_instructions(
                    instructions1, instructions2
                )

        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            changes["instruction_comparison_failed"] = True

        return changes

    def _compare_instructions(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare instruction-level differences."""
        instruction_diff = {
            "modified_instructions": [],
            "new_instruction_patterns": [],
            "removed_instruction_patterns": [],
            "opcode_distribution_change": {},
        }

        try:
            # Get functions for comparison
            functions1 = r2_1.get_functions()[:10]  # Limit for performance
            functions2 = r2_2.get_functions()[:10]

            # Compare common functions at instruction level
            for func1 in functions1:
                # Find corresponding function in binary2
                func1_name = func1.get("name", "")
                func2 = next((f for f in functions2 if f.get("name") == func1_name), None)

                if func2:
                    # Compare instructions
                    addr1 = func1.get("offset", 0)
                    addr2 = func2.get("offset", 0)

                    if addr1 and addr2:
                        disasm1 = r2_1._execute_command(f"pdf @ {hex(addr1)}")
                        disasm2 = r2_2._execute_command(f"pdf @ {hex(addr2)}")

                        inst_changes = self._analyze_instruction_changes(
                            disasm1, disasm2, func1_name
                        )
                        if inst_changes:
                            instruction_diff["modified_instructions"].extend(inst_changes)

            # Analyze opcode distribution changes
            opcodes1 = self._extract_opcode_distribution(r2_1, functions1)
            opcodes2 = self._extract_opcode_distribution(r2_2, functions2)
            instruction_diff["opcode_distribution_change"] = self._compare_opcode_distributions(
                opcodes1, opcodes2
            )

        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            instruction_diff["error"] = "Failed to compare instructions"

        return instruction_diff

    def _compare_strings(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare strings between binaries."""
        try:
            # Get strings from both binaries
            strings1_data = r2_1._execute_command("izzj", expect_json=True)
            strings2_data = r2_2._execute_command("izzj", expect_json=True)

            if not isinstance(strings1_data, list) or not isinstance(strings2_data, list):
                return {"error": "Failed to get string data"}

            strings1 = {s.get("string", ""): s for s in strings1_data}
            strings2 = {s.get("string", ""): s for s in strings2_data}

            str_set1 = set(strings1.keys())
            str_set2 = set(strings2.keys())

            added_strings = str_set2 - str_set1
            removed_strings = str_set1 - str_set2
            common_strings = str_set1 & str_set2

            # Analyze string changes by category
            license_changes = self._analyze_license_string_changes(added_strings, removed_strings)
            error_message_changes = self._analyze_error_message_changes(
                added_strings, removed_strings
            )
            debug_changes = self._analyze_debug_string_changes(added_strings, removed_strings)

            return {
                "total_strings": {
                    "binary1": len(strings1),
                    "binary2": len(strings2),
                },
                "added_strings": list(added_strings)[:50],  # Limit output
                "removed_strings": list(removed_strings)[:50],
                "common_strings_count": len(common_strings),
                "string_similarity": len(common_strings) / max(1, len(str_set1 | str_set2)),
                "license_string_changes": license_changes,
                "error_message_changes": error_message_changes,
                "debug_string_changes": debug_changes,
                "significant_additions": self._identify_significant_string_additions(added_strings),
                "significant_removals": self._identify_significant_string_removals(removed_strings),
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare strings"}

    def _compare_imports_exports(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare imports and exports."""
        try:
            # Get imports
            imports1_data = r2_1._execute_command("iij", expect_json=True)
            imports2_data = r2_2._execute_command("iij", expect_json=True)

            # Get exports
            exports1_data = r2_1._execute_command("iEj", expect_json=True)
            exports2_data = r2_2._execute_command("iEj", expect_json=True)

            # Process imports
            imports1 = {imp.get("name", ""): imp for imp in (imports1_data or [])}
            imports2 = {imp.get("name", ""): imp for imp in (imports2_data or [])}

            import_names1 = set(imports1.keys())
            import_names2 = set(imports2.keys())

            # Process exports
            exports1 = {exp.get("name", ""): exp for exp in (exports1_data or [])}
            exports2 = {exp.get("name", ""): exp for exp in (exports2_data or [])}

            export_names1 = set(exports1.keys())
            export_names2 = set(exports2.keys())

            return {
                "import_changes": {
                    "added": list(import_names2 - import_names1),
                    "removed": list(import_names1 - import_names2),
                    "total_binary1": len(imports1),
                    "total_binary2": len(imports2),
                    "security_impact": self._assess_import_security_impact(
                        import_names2 - import_names1, import_names1 - import_names2
                    ),
                },
                "export_changes": {
                    "added": list(export_names2 - export_names1),
                    "removed": list(export_names1 - export_names2),
                    "total_binary1": len(exports1),
                    "total_binary2": len(exports2),
                },
                "dll_dependency_changes": self._analyze_dll_dependency_changes(imports1, imports2),
                "api_usage_changes": self._analyze_api_usage_changes(import_names1, import_names2),
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare imports/exports"}

    def _compare_sections(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare binary sections."""
        try:
            sections1_data = r2_1._execute_command("iSj", expect_json=True)
            sections2_data = r2_2._execute_command("iSj", expect_json=True)

            if not isinstance(sections1_data, list) or not isinstance(sections2_data, list):
                return {"error": "Failed to get section data"}

            sections1 = {s.get("name", ""): s for s in sections1_data}
            sections2 = {s.get("name", ""): s for s in sections2_data}

            section_names1 = set(sections1.keys())
            section_names2 = set(sections2.keys())

            added_sections = section_names2 - section_names1
            removed_sections = section_names1 - section_names2
            common_sections = section_names1 & section_names2

            # Analyze changes in common sections
            modified_sections = []
            for section_name in common_sections:
                sec1 = sections1[section_name]
                sec2 = sections2[section_name]

                changes = {}
                if sec1.get("vsize") != sec2.get("vsize"):
                    changes["size_change"] = sec2.get("vsize", 0) - sec1.get("vsize", 0)
                if sec1.get("perm") != sec2.get("perm"):
                    changes["permission_change"] = {
                        "old": sec1.get("perm", ""),
                        "new": sec2.get("perm", ""),
                    }
                if sec1.get("vaddr") != sec2.get("vaddr"):
                    changes["address_change"] = sec2.get("vaddr", 0) - sec1.get("vaddr", 0)

                if changes:
                    modified_sections.append(
                        {
                            "name": section_name,
                            "changes": changes,
                        }
                    )

            return {
                "added_sections": list(added_sections),
                "removed_sections": list(removed_sections),
                "modified_sections": modified_sections,
                "total_sections": {
                    "binary1": len(sections1),
                    "binary2": len(sections2),
                },
                "section_layout_change": len(added_sections) > 0
                or len(removed_sections) > 0
                or len(modified_sections) > 0,
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare sections"}

    def _compare_entry_points(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare entry points."""
        try:
            info1 = r2_1.get_info()
            info2 = r2_2.get_info()

            entry1 = info1.get("bin", {}).get("baddr", 0)
            entry2 = info2.get("bin", {}).get("baddr", 0)

            return {
                "entry_point_change": entry1 != entry2,
                "entry_point_binary1": hex(entry1) if entry1 else "0x0",
                "entry_point_binary2": hex(entry2) if entry2 else "0x0",
                "address_diff": entry2 - entry1 if entry1 and entry2 else 0,
            }
        except R2Exception as e:
            self.logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare entry points"}

    def _compare_security_features(self, r2_1, r2_2) -> dict[str, Any]:
        """Compare security features."""
        try:
            info1 = r2_1.get_info()
            info2 = r2_2.get_info()

            bin1 = info1.get("bin", {})
            bin2 = info2.get("bin", {})

            security_features = ["canary", "nx", "pic", "stripped"]
            changes = {}

            for feature in security_features:
                val1 = bin1.get(feature, False)
                val2 = bin2.get(feature, False)

                if val1 != val2:
                    changes[feature] = {
                        "binary1": val1,
                        "binary2": val2,
                        "security_impact": self._assess_security_feature_impact(
                            feature, val1, val2
                        ),
                    }

            return {
                "security_changes": changes,
                "overall_security_change": "improved"
                if any(c.get("security_impact") == "improved" for c in changes.values())
                else "degraded"
                if any(c.get("security_impact") == "degraded" for c in changes.values())
                else "unchanged",
            }
        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            return {"error": "Failed to compare security features"}

    def _analyze_patches(self, r2_1, r2_2) -> dict[str, Any]:
        """Analyze patches between binaries."""
        patch_analysis = {
            "potential_patches": [],
            "patch_categories": {},
            "security_patches": [],
            "functionality_patches": [],
            "performance_patches": [],
        }

        try:
            # Get functions from both binaries
            functions1 = {f["name"]: f for f in r2_1.get_functions()}
            functions2 = {f["name"]: f for f in r2_2.get_functions()}

            # Analyze modified functions for patch patterns
            for name in set(functions1.keys()) & set(functions2.keys()):
                func1 = functions1[name]
                func2 = functions2[name]

                # Check for size changes that might indicate patches
                size_change = func2.get("size", 0) - func1.get("size", 0)

                if abs(size_change) > 0:
                    patch_info = {
                        "function": name,
                        "size_change": size_change,
                        "patch_type": self._classify_patch_type(name, size_change),
                        "impact_assessment": self._assess_patch_impact(name, size_change),
                    }

                    patch_analysis["potential_patches"].append(patch_info)

                    # Categorize patches
                    patch_type = patch_info["patch_type"]
                    if patch_type not in patch_analysis["patch_categories"]:
                        patch_analysis["patch_categories"][patch_type] = 0
                    patch_analysis["patch_categories"][patch_type] += 1

                    # Special categorization
                    if "security" in patch_type.lower():
                        patch_analysis["security_patches"].append(patch_info)
                    elif "functionality" in patch_type.lower():
                        patch_analysis["functionality_patches"].append(patch_info)
                    elif "performance" in patch_type.lower():
                        patch_analysis["performance_patches"].append(patch_info)

            # Analyze overall patch impact
            patch_analysis["total_patches"] = len(patch_analysis["potential_patches"])
            patch_analysis["patch_density"] = len(patch_analysis["potential_patches"]) / max(
                1, len(functions1)
            )

        except R2Exception as e:
            logger.error("R2Exception in radare2_binary_diff: %s", e)
            patch_analysis["error"] = "Failed to analyze patches"

        return patch_analysis

    def _calculate_similarity_metrics(self, diff_result: dict[str, Any]) -> dict[str, float]:
        """Calculate various similarity metrics."""
        metrics = {}

        try:
            # Function similarity
            func_diff = diff_result.get("function_diff", {})
            metrics["function_similarity"] = func_diff.get("function_similarity", 0.0)

            # String similarity
            string_diff = diff_result.get("string_diff", {})
            metrics["string_similarity"] = string_diff.get("string_similarity", 0.0)

            # Import similarity
            import_export_diff = diff_result.get("import_export_diff", {})
            import_changes = import_export_diff.get("import_changes", {})
            total_imports = max(
                import_changes.get("total_binary1", 1), import_changes.get("total_binary2", 1)
            )
            changed_imports = len(import_changes.get("added", [])) + len(
                import_changes.get("removed", [])
            )
            metrics["import_similarity"] = 1.0 - (changed_imports / total_imports)

            # Overall binary similarity
            metrics["overall_similarity"] = (
                metrics["function_similarity"] * 0.4
                + metrics["string_similarity"] * 0.3
                + metrics["import_similarity"] * 0.3
            )

            # Change magnitude
            metadata_diff = diff_result.get("metadata_diff", {})
            file_size_change = abs(metadata_diff.get("file_size_diff", 0))
            metrics["change_magnitude"] = min(1.0, file_size_change / 1000000)  # Normalize by MB

        except Exception as e:
            logger.error("Exception in radare2_binary_diff: %s", e)
            metrics = {"error": "Failed to calculate similarity metrics"}

        return metrics

    def _generate_change_summary(self, diff_result: dict[str, Any]) -> dict[str, Any]:
        """Generate high-level change summary."""
        summary = {
            "change_type": "unknown",
            "major_changes": [],
            "minor_changes": [],
            "impact_assessment": "low",
            "recommended_actions": [],
        }

        try:
            # Analyze function changes
            func_diff = diff_result.get("function_diff", {})
            if func_diff.get("major_changes", False):
                summary["major_changes"].append("Significant function modifications")
                summary["change_type"] = "major_update"

            # Analyze security changes
            security_diff = diff_result.get("security_diff", {})
            security_changes = security_diff.get("security_changes", {})
            if security_changes:
                if any(c.get("security_impact") == "improved" for c in security_changes.values()):
                    summary["major_changes"].append("Security improvements")
                elif any(c.get("security_impact") == "degraded" for c in security_changes.values()):
                    summary["major_changes"].append("Security degradation")

            # Analyze patch impact
            patch_analysis = diff_result.get("patch_analysis", {})
            if patch_analysis.get("total_patches", 0) > 0:
                summary["minor_changes"].append(
                    f"{patch_analysis['total_patches']} function patches detected"
                )

            # Determine impact assessment
            if len(summary["major_changes"]) > 2:
                summary["impact_assessment"] = "high"
            elif len(summary["major_changes"]) > 0:
                summary["impact_assessment"] = "medium"

            # Generate recommendations
            if "Security degradation" in summary["major_changes"]:
                summary["recommended_actions"].append("Review security implications")
            if func_diff.get("major_changes", False):
                summary["recommended_actions"].append("Analyze functional changes")
            if patch_analysis.get("total_patches", 0) > 10:
                summary["recommended_actions"].append("Detailed patch analysis recommended")

        except Exception as e:
            logger.error("Exception in radare2_binary_diff: %s", e)
            summary["error"] = "Failed to generate change summary"

        return summary

    def _assess_vulnerability_impact(self, diff_result: dict[str, Any]) -> dict[str, Any]:
        """Assess vulnerability impact of changes."""
        impact = {
            "new_vulnerabilities": [],
            "fixed_vulnerabilities": [],
            "risk_level": "low",
            "security_recommendations": [],
        }

        try:
            # Analyze import changes for security impact
            import_export_diff = diff_result.get("import_export_diff", {})
            import_changes = import_export_diff.get("import_changes", {})

            added_imports = import_changes.get("added", [])
            removed_imports = import_changes.get("removed", [])

            # Check for dangerous API additions
            dangerous_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
            for api in added_imports:
                if any(dangerous in api for dangerous in dangerous_apis):
                    impact["new_vulnerabilities"].append(
                        {
                            "type": "dangerous_api_addition",
                            "api": api,
                            "risk": "high",
                        }
                    )

            # Check for security API removals
            security_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
            for api in removed_imports:
                if any(sec_api in api for sec_api in security_apis):
                    impact["new_vulnerabilities"].append(
                        {
                            "type": "security_check_removal",
                            "api": api,
                            "risk": "medium",
                        }
                    )

            # Analyze security feature changes
            security_diff = diff_result.get("security_diff", {})
            security_changes = security_diff.get("security_changes", {})

            for feature, change in security_changes.items():
                if change.get("security_impact") == "degraded":
                    impact["new_vulnerabilities"].append(
                        {
                            "type": "security_feature_degradation",
                            "feature": feature,
                            "risk": "high",
                        }
                    )
                elif change.get("security_impact") == "improved":
                    impact["fixed_vulnerabilities"].append(
                        {
                            "type": "security_feature_improvement",
                            "feature": feature,
                        }
                    )

            # Determine overall risk level
            high_risk_count = sum(
                1 for v in impact["new_vulnerabilities"] if v.get("risk") == "high"
            )
            if high_risk_count > 0:
                impact["risk_level"] = "high"
            elif len(impact["new_vulnerabilities"]) > 0:
                impact["risk_level"] = "medium"

            # Generate recommendations
            if impact["risk_level"] == "high":
                impact["security_recommendations"].append("Immediate security review required")
            if len(impact["new_vulnerabilities"]) > 0:
                impact["security_recommendations"].append("Vulnerability assessment recommended")

        except Exception as e:
            logger.error("Exception in radare2_binary_diff: %s", e)
            impact["error"] = "Failed to assess vulnerability impact"

        return impact

    # Helper methods
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.logger.error("Exception in radare2_binary_diff: %s", e)
            return "error_calculating_hash"

    def _extract_instructions(self, disasm: str) -> list[str]:
        """Extract instructions from disassembly."""
        instructions = []
        for line in disasm.split("\n"):
            line = line.strip()
            if line and not line.startswith(";") and "0x" in line:
                # Extract instruction part
                parts = line.split()
                if len(parts) >= 2:
                    instructions.append(" ".join(parts[1:]))
        return instructions

    def _diff_instructions(
        self, instructions1: list[str], instructions2: list[str]
    ) -> list[dict[str, Any]]:
        """Diff instruction sequences."""
        matcher = SequenceMatcher(None, instructions1, instructions2)
        changes = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                changes.append(
                    {
                        "type": tag,
                        "old_instructions": instructions1[i1:i2],
                        "new_instructions": instructions2[j1:j2],
                        "line_range": f"{i1}-{i2}",
                    }
                )

        return changes

    def _analyze_instruction_changes(
        self, disasm1: str, disasm2: str, func_name: str
    ) -> list[dict[str, Any]]:
        """Analyze instruction-level changes."""
        instructions1 = self._extract_instructions(disasm1)
        instructions2 = self._extract_instructions(disasm2)

        changes = []
        matcher = SequenceMatcher(None, instructions1, instructions2)

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                changes.append(
                    {
                        "function": func_name,
                        "change_type": tag,
                        "old_instructions": instructions1[i1:i2],
                        "new_instructions": instructions2[j1:j2],
                    }
                )

        return changes

    def _extract_opcode_distribution(self, r2, functions: list[dict[str, Any]]) -> dict[str, int]:
        """Extract opcode distribution from functions."""
        opcodes = {}

        for func in functions[:5]:  # Limit for performance
            addr = func.get("offset", 0)
            if addr:
                try:
                    disasm = r2._execute_command(f"pdf @ {hex(addr)}")
                    for line in disasm.split("\n"):
                        parts = line.strip().split()
                        if len(parts) >= 2 and "0x" in parts[0]:
                            opcode = parts[1]
                            opcodes[opcode] = opcodes.get(opcode, 0) + 1
                except R2Exception as e:
                    self.logger.error("R2Exception in radare2_binary_diff: %s", e)
                    continue

        return opcodes

    def _compare_opcode_distributions(
        self, opcodes1: dict[str, int], opcodes2: dict[str, int]
    ) -> dict[str, Any]:
        """Compare opcode distributions."""
        all_opcodes = set(opcodes1.keys()) | set(opcodes2.keys())

        changes = {}
        for opcode in all_opcodes:
            count1 = opcodes1.get(opcode, 0)
            count2 = opcodes2.get(opcode, 0)

            if count1 != count2:
                changes[opcode] = {
                    "binary1_count": count1,
                    "binary2_count": count2,
                    "change": count2 - count1,
                }

        return changes

    def _analyze_license_string_changes(
        self, added: set[str], removed: set[str]
    ) -> dict[str, list[str]]:
        """Analyze license-related string changes."""
        license_keywords = [
            "license",
            "trial",
            "demo",
            "registration",
            "activation",
            "serial",
            "key",
        ]

        license_added = [s for s in added if any(kw in s.lower() for kw in license_keywords)]
        license_removed = [s for s in removed if any(kw in s.lower() for kw in license_keywords)]

        return {
            "added_license_strings": license_added,
            "removed_license_strings": license_removed,
        }

    def _analyze_error_message_changes(
        self, added: set[str], removed: set[str]
    ) -> dict[str, list[str]]:
        """Analyze error message changes."""
        error_keywords = ["error", "fail", "invalid", "cannot", "unable"]

        error_added = [s for s in added if any(kw in s.lower() for kw in error_keywords)]
        error_removed = [s for s in removed if any(kw in s.lower() for kw in error_keywords)]

        return {
            "added_error_messages": error_added,
            "removed_error_messages": error_removed,
        }

    def _analyze_debug_string_changes(
        self, added: set[str], removed: set[str]
    ) -> dict[str, list[str]]:
        """Analyze debug string changes."""
        debug_keywords = ["debug", "trace", "log", "verbose"]

        debug_added = [s for s in added if any(kw in s.lower() for kw in debug_keywords)]
        debug_removed = [s for s in removed if any(kw in s.lower() for kw in debug_keywords)]

        return {
            "added_debug_strings": debug_added,
            "removed_debug_strings": debug_removed,
        }

    def _identify_significant_string_additions(self, added_strings: set[str]) -> list[str]:
        """Identify significant string additions."""
        significant = []

        for string in added_strings:
            if len(string) > 20 and any(
                keyword in string.lower() for keyword in ["license", "error", "warning", "invalid"]
            ):
                significant.append(string)

        return significant[:10]  # Limit output

    def _identify_significant_string_removals(self, removed_strings: set[str]) -> list[str]:
        """Identify significant string removals."""
        significant = []

        for string in removed_strings:
            if len(string) > 20 and any(
                keyword in string.lower() for keyword in ["license", "error", "warning", "invalid"]
            ):
                significant.append(string)

        return significant[:10]  # Limit output

    def _assess_import_security_impact(
        self, added_imports: set[str], removed_imports: set[str]
    ) -> str:
        """Assess security impact of import changes."""
        dangerous_apis = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetWindowsHookEx",
        ]
        security_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]

        has_dangerous_additions = any(
            api for api in added_imports if any(d in api for d in dangerous_apis)
        )
        has_security_removals = any(
            api for api in removed_imports if any(s in api for s in security_apis)
        )

        if has_dangerous_additions:
            return "high_risk"
        if has_security_removals:
            return "medium_risk"
        return "low_risk"

    def _analyze_dll_dependency_changes(
        self, imports1: dict[str, Any], imports2: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze DLL dependency changes."""
        libs1 = set(imp.get("libname", "") for imp in imports1.values())
        libs2 = set(imp.get("libname", "") for imp in imports2.values())

        return {
            "added_dependencies": list(libs2 - libs1),
            "removed_dependencies": list(libs1 - libs2),
            "common_dependencies": list(libs1 & libs2),
        }

    def _analyze_api_usage_changes(self, imports1: set[str], imports2: set[str]) -> dict[str, Any]:
        """Analyze API usage pattern changes."""
        crypto_apis = [api for api in (imports1 | imports2) if "crypt" in api.lower()]
        network_apis = [
            api
            for api in (imports1 | imports2)
            if any(net in api.lower() for net in ["socket", "http", "internet"])
        ]

        crypto_change = len([api for api in crypto_apis if api in imports2]) - len(
            [api for api in crypto_apis if api in imports1]
        )
        network_change = len([api for api in network_apis if api in imports2]) - len(
            [api for api in network_apis if api in imports1]
        )

        return {
            "crypto_api_usage_change": crypto_change,
            "network_api_usage_change": network_change,
            "overall_api_complexity_change": len(imports2) - len(imports1),
        }

    def _assess_security_feature_impact(self, feature: str, old_val: bool, new_val: bool) -> str:
        """Assess impact of security feature change."""
        security_features = ["canary", "nx", "pic"]

        if feature in security_features:
            if not old_val and new_val:
                return "improved"
            if old_val and not new_val:
                return "degraded"

        return "neutral"

    def _classify_patch_type(self, function_name: str, size_change: int) -> str:
        """Classify type of patch based on function name and size change."""
        name_lower = function_name.lower()

        if any(keyword in name_lower for keyword in ["license", "valid", "check"]):
            return "license_validation_patch"
        if any(keyword in name_lower for keyword in ["security", "auth", "crypt"]):
            return "security_patch"
        if size_change > 0:
            return "functionality_enhancement"
        if size_change < 0:
            return "code_optimization"
        return "unknown_patch"

    def _assess_patch_impact(self, function_name: str, size_change: int) -> str:
        """Assess impact of patch based on size change and function importance."""
        # Base impact assessment from size change
        if abs(size_change) > 100:
            base_impact = "high"
        elif abs(size_change) > 20:
            base_impact = "medium"
        else:
            base_impact = "low"

        # Function name-based impact assessment
        critical_functions = [
            "main",
            "wmain",
            "DllMain",
            "entry",
            "start",
            "_start",
            "license",
            "activate",
            "verify",
            "check",
            "validate",
            "decrypt",
            "encrypt",
            "hash",
            "sign",
            "auth",
        ]

        security_functions = [
            "malloc",
            "free",
            "strcpy",
            "strcat",
            "sprintf",
            "scanf",
            "gets",
            "system",
            "exec",
            "CreateProcess",
            "VirtualAlloc",
        ]

        # Upgrade impact if function is critical
        function_lower = function_name.lower()
        if any(critical in function_lower for critical in critical_functions):
            if base_impact == "low":
                return "medium"
            if base_impact == "medium":
                return "high"
            return "critical"

        # Upgrade impact if function is security-sensitive
        if any(security in function_lower for security in security_functions):
            if base_impact == "low":
                return "medium"
            return "high"

        # Check for common vulnerability patterns in function name
        vuln_patterns = ["overflow", "buffer", "format", "injection", "xss", "sql"]
        if any(pattern in function_lower for pattern in vuln_patterns):
            return "high"

        return base_impact


def compare_binaries(
    binary1_path: str, binary2_path: str, radare2_path: str | None = None
) -> dict[str, Any]:
    """Perform comprehensive binary comparison.

    Args:
        binary1_path: Path to first binary
        binary2_path: Path to second binary
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete binary comparison results

    """
    differ = R2BinaryDiff(binary1_path, binary2_path, radare2_path)
    return differ.analyze_differences()


__all__ = ["R2BinaryDiff", "compare_binaries"]
