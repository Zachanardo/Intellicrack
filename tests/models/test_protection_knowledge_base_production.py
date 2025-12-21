"""Production tests for protection knowledge base.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.models.protection_knowledge_base import (
    BypassDifficulty,
    BypassTechnique,
    ProtectionCategory,
    ProtectionKnowledgeBase,
    ProtectionSchemeInfo,
    get_protection_knowledge_base,
)


class TestProtectionKnowledgeBase:
    """Test protection knowledge base functionality."""

    def test_knowledge_base_initialization(self) -> None:
        """Knowledge base initializes with protection schemes and strategies."""
        kb = ProtectionKnowledgeBase()

        assert len(kb.protection_schemes) > 0
        assert len(kb.bypass_strategies) > 0
        assert len(kb.analysis_workflows) > 0

    def test_protection_schemes_include_major_protections(self) -> None:
        """Protection schemes include all major commercial protections."""
        kb = ProtectionKnowledgeBase()

        required_protections = [
            "sentinel_hasp",
            "flexlm",
            "winlicense",
            "vmprotect",
            "steam_ceg",
            "denuvo",
            "microsoft_activation",
        ]

        for protection in required_protections:
            assert protection in kb.protection_schemes, f"Missing {protection}"

    def test_get_protection_info_retrieves_by_exact_name(self) -> None:
        """Get protection info retrieves scheme by exact key."""
        kb = ProtectionKnowledgeBase()

        info = kb.get_protection_info("vmprotect")

        assert info is not None
        assert info.name == "VMProtect"
        assert info.vendor == "VMProtect Software"

    def test_get_protection_info_handles_partial_match(self) -> None:
        """Get protection info handles partial name matching."""
        kb = ProtectionKnowledgeBase()

        info = kb.get_protection_info("Sentinel HASP")

        assert info is not None
        assert "Sentinel" in info.name or "HASP" in info.name

    def test_get_protection_info_case_insensitive(self) -> None:
        """Get protection info is case insensitive."""
        kb = ProtectionKnowledgeBase()

        info1 = kb.get_protection_info("VMPROTECT")
        info2 = kb.get_protection_info("vmprotect")
        info3 = kb.get_protection_info("VMProtect")

        assert info1 is not None
        assert info2 is not None
        assert info3 is not None
        assert info1.name == info2.name == info3.name

    def test_get_protection_info_returns_none_for_unknown(self) -> None:
        """Get protection info returns None for unknown protection."""
        kb = ProtectionKnowledgeBase()

        info = kb.get_protection_info("nonexistent_protection")

        assert info is None

    def test_protection_info_contains_bypass_techniques(self) -> None:
        """Protection info contains actionable bypass techniques."""
        kb = ProtectionKnowledgeBase()

        hasp_info = kb.get_protection_info("sentinel_hasp")

        assert hasp_info is not None
        assert len(hasp_info.bypass_techniques) > 0
        assert all(isinstance(t, BypassTechnique) for t in hasp_info.bypass_techniques)

    def test_bypass_technique_includes_required_fields(self) -> None:
        """Bypass techniques include all required information."""
        kb = ProtectionKnowledgeBase()

        vmprotect_info = kb.get_protection_info("vmprotect")

        assert vmprotect_info is not None
        for technique in vmprotect_info.bypass_techniques:
            assert technique.name
            assert technique.description
            assert technique.difficulty
            assert len(technique.tools_required) > 0
            assert 0.0 <= technique.success_rate <= 1.0
            assert technique.time_estimate

    def test_bypass_difficulty_reflects_actual_difficulty(self) -> None:
        """Bypass difficulty accurately reflects protection strength."""
        kb = ProtectionKnowledgeBase()

        test_cases = [
            ("asprotect", [BypassDifficulty.LOW, BypassDifficulty.TRIVIAL]),
            ("vmprotect", [BypassDifficulty.EXTREME, BypassDifficulty.VERY_HIGH]),
            ("denuvo", [BypassDifficulty.EXTREME]),
            ("steam_ceg", [BypassDifficulty.MEDIUM, BypassDifficulty.LOW]),
        ]

        for protection, expected_difficulties in test_cases:
            info = kb.get_protection_info(protection)
            assert info is not None
            assert info.bypass_difficulty in expected_difficulties, f"{protection} difficulty mismatch"

    def test_detection_signatures_identify_protections(self) -> None:
        """Detection signatures contain actual protection artifacts."""
        kb = ProtectionKnowledgeBase()

        test_cases = [
            ("sentinel_hasp", ["hasp_login", "hasplms.exe", "aksusbd.sys"]),
            ("flexlm", ["lmgrd", "lmutil", "license.dat"]),
            ("vmprotect", [".vmp0", ".vmp1", "VMProtectBegin"]),
            ("steam_ceg", ["steam_api.dll", "SteamAPI_Init"]),
        ]

        for protection, expected_sigs in test_cases:
            info = kb.get_protection_info(protection)
            assert info is not None
            for sig in expected_sigs:
                assert any(sig.lower() in s.lower() for s in info.detection_signatures), f"Missing signature {sig} in {protection}"

    def test_search_by_signature_finds_protections(self) -> None:
        """Search by signature finds protections containing signature."""
        kb = ProtectionKnowledgeBase()

        results = kb.search_by_signature("hasp")

        assert len(results) > 0
        assert any("HASP" in r.name or "Sentinel" in r.name for r in results)

    def test_search_by_signature_case_insensitive(self) -> None:
        """Search by signature is case insensitive."""
        kb = ProtectionKnowledgeBase()

        results_lower = kb.search_by_signature("steam")
        results_upper = kb.search_by_signature("STEAM")

        assert len(results_lower) == len(results_upper)

    def test_get_bypass_techniques_returns_technique_list(self) -> None:
        """Get bypass techniques returns list of techniques for protection."""
        kb = ProtectionKnowledgeBase()

        techniques = kb.get_bypass_techniques("vmprotect")

        assert len(techniques) > 0
        assert all(isinstance(t, BypassTechnique) for t in techniques)

    def test_get_tools_for_protection_aggregates_tools(self) -> None:
        """Get tools for protection aggregates all required tools."""
        kb = ProtectionKnowledgeBase()

        tools = kb.get_tools_for_protection("vmprotect")

        assert len(tools) > 0
        assert isinstance(tools, list)
        assert all(isinstance(t, str) for t in tools)

    def test_get_tools_for_protection_deduplicates(self) -> None:
        """Get tools for protection removes duplicates."""
        kb = ProtectionKnowledgeBase()

        tools = kb.get_tools_for_protection("sentinel_hasp")

        assert len(tools) == len(set(tools))

    def test_estimate_bypass_time_adjusts_for_skill(self) -> None:
        """Estimate bypass time adjusts based on skill level."""
        kb = ProtectionKnowledgeBase()

        beginner_time = kb.estimate_bypass_time("steam_ceg", "beginner")
        expert_time = kb.estimate_bypass_time("steam_ceg", "expert")

        assert beginner_time != expert_time

    def test_estimate_bypass_time_realistic_estimates(self) -> None:
        """Estimate bypass time provides realistic time estimates."""
        kb = ProtectionKnowledgeBase()

        test_cases = [
            ("asprotect", "advanced", ["minute", "hour"]),
            ("vmprotect", "expert", ["week", "month"]),
            ("denuvo", "expert", ["month"]),
        ]

        for protection, skill, expected_units in test_cases:
            estimate = kb.estimate_bypass_time(protection, skill)
            assert any(unit in estimate.lower() for unit in expected_units), f"Unrealistic estimate for {protection}: {estimate}"

    def test_get_analysis_workflow_returns_steps(self) -> None:
        """Get analysis workflow returns ordered steps."""
        kb = ProtectionKnowledgeBase()

        workflow = kb.get_analysis_workflow("initial_analysis")

        assert len(workflow) > 0
        assert all(isinstance(step, str) for step in workflow)

    def test_analysis_workflows_cover_full_process(self) -> None:
        """Analysis workflows cover complete analysis process."""
        kb = ProtectionKnowledgeBase()

        required_workflows = [
            "initial_analysis",
            "static_analysis",
            "dynamic_analysis",
            "protection_removal",
            "validation",
        ]

        for workflow in required_workflows:
            steps = kb.get_analysis_workflow(workflow)
            assert len(steps) > 0, f"Missing workflow: {workflow}"

    def test_bypass_strategies_organized_by_category(self) -> None:
        """Bypass strategies are organized by protection category."""
        kb = ProtectionKnowledgeBase()

        required_categories = [
            "hardware_dongle",
            "network_license",
            "software_protection",
            "gaming_drm",
            "time_based",
        ]

        for category in required_categories:
            assert category in kb.bypass_strategies
            assert len(kb.bypass_strategies[category]) > 0

    def test_export_knowledge_base_creates_valid_json(self, tmp_path: Path) -> None:
        """Export knowledge base creates valid JSON file."""
        kb = ProtectionKnowledgeBase()

        output_path = str(tmp_path / "kb_export.json")
        kb.export_knowledge_base(output_path)

        assert os.path.exists(output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert "protection_schemes" in data
        assert "bypass_strategies" in data
        assert "analysis_workflows" in data

    def test_exported_json_contains_complete_data(self, tmp_path: Path) -> None:
        """Exported JSON contains all protection scheme data."""
        kb = ProtectionKnowledgeBase()

        output_path = str(tmp_path / "kb_export.json")
        kb.export_knowledge_base(output_path)

        with open(output_path) as f:
            data = json.load(f)

        vmprotect = data["protection_schemes"]["vmprotect"]

        assert vmprotect["name"] == "VMProtect"
        assert vmprotect["vendor"] == "VMProtect Software"
        assert vmprotect["category"] == "virtualization"
        assert len(vmprotect["bypass_techniques"]) > 0
        assert len(vmprotect["detection_signatures"]) > 0

    def test_exported_bypass_techniques_complete(self, tmp_path: Path) -> None:
        """Exported bypass techniques include all fields."""
        kb = ProtectionKnowledgeBase()

        output_path = str(tmp_path / "kb_export.json")
        kb.export_knowledge_base(output_path)

        with open(output_path) as f:
            data = json.load(f)

        hasp = data["protection_schemes"]["sentinel_hasp"]
        technique = hasp["bypass_techniques"][0]

        assert "name" in technique
        assert "description" in technique
        assert "difficulty" in technique
        assert "tools_required" in technique
        assert "success_rate" in technique
        assert "time_estimate" in technique
        assert "risks" in technique
        assert "prerequisites" in technique

    def test_singleton_pattern_returns_same_instance(self) -> None:
        """get_protection_knowledge_base returns singleton instance."""
        kb1 = get_protection_knowledge_base()
        kb2 = get_protection_knowledge_base()

        assert kb1 is kb2

    def test_common_applications_list_real_software(self) -> None:
        """Common applications list includes real commercial software."""
        kb = ProtectionKnowledgeBase()

        test_cases = [
            ("sentinel_hasp", ["AutoCAD", "MATLAB", "SolidWorks"]),
            ("flexlm", ["ANSYS", "MATLAB", "Cadence"]),
            ("microsoft_activation", ["Windows", "Office"]),
        ]

        for protection, expected_apps in test_cases:
            info = kb.get_protection_info(protection)
            assert info is not None
            for app in expected_apps:
                assert any(app.lower() in a.lower() for a in info.common_applications), f"Missing {app} in {protection}"

    def test_analysis_tips_provide_actionable_guidance(self) -> None:
        """Analysis tips provide specific actionable guidance."""
        kb = ProtectionKnowledgeBase()

        vmprotect_info = kb.get_protection_info("vmprotect")

        assert vmprotect_info is not None
        assert len(vmprotect_info.analysis_tips) > 0
        assert all(len(tip) > 10 for tip in vmprotect_info.analysis_tips)

    def test_common_mistakes_warn_about_real_pitfalls(self) -> None:
        """Common mistakes warn about actual bypass pitfalls."""
        kb = ProtectionKnowledgeBase()

        hasp_info = kb.get_protection_info("sentinel_hasp")

        assert hasp_info is not None
        assert len(hasp_info.common_mistakes) > 0
        assert all(len(mistake) > 10 for mistake in hasp_info.common_mistakes)

    def test_protection_categories_accurately_classify(self) -> None:
        """Protection categories accurately classify protection types."""
        kb = ProtectionKnowledgeBase()

        test_cases = [
            ("sentinel_hasp", ProtectionCategory.HARDWARE_DONGLE),
            ("flexlm", ProtectionCategory.NETWORK_LICENSE),
            ("vmprotect", ProtectionCategory.VIRTUALIZATION),
            ("steam_ceg", ProtectionCategory.GAMING_DRM),
            ("microsoft_activation", ProtectionCategory.ENTERPRISE),
        ]

        for protection, expected_category in test_cases:
            info = kb.get_protection_info(protection)
            assert info is not None
            assert info.category == expected_category, f"{protection} category mismatch"

    def test_success_rates_realistic_and_consistent(self) -> None:
        """Success rates are realistic and consistent with difficulty."""
        kb = ProtectionKnowledgeBase()

        denuvo_info = kb.get_protection_info("denuvo")

        assert denuvo_info is not None
        for technique in denuvo_info.bypass_techniques:
            if technique.difficulty == BypassDifficulty.EXTREME:
                assert technique.success_rate <= 0.5, "EXTREME difficulty should have low success rate"

    def test_resources_provide_references(self) -> None:
        """Resources provide useful references for bypass research."""
        kb = ProtectionKnowledgeBase()

        info = kb.get_protection_info("vmprotect")

        assert info is not None
        assert len(info.resources) > 0
        assert all(isinstance(r, str) and len(r) > 0 for r in info.resources)
