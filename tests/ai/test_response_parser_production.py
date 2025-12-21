"""Production tests for AI response parser.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import pytest

from intellicrack.ai.response_parser import (
    parse_ai_response_sections,
    parse_attack_vector_response,
    parse_security_analysis_response,
    parse_simple_response,
)


class TestParseAIResponseSections:
    """Test AI response section parsing with real response formats."""

    def test_parse_sections_with_clear_keywords(self) -> None:
        """Parser correctly identifies and extracts sections by keyword headers."""
        response = """
        Vulnerability Analysis:
        The vulnerability in this binary is critical.
        The security issue involves buffer overflow.
        Risk level is high.

        Recommendations:
        We recommend patching immediately.
        You should validate all inputs.
        Suggested mitigation: implement bounds checking.
        """

        section_keywords = {
            "insights": ["vulnerability"],
            "suggestions": ["recommendations"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        assert "insights" in result
        assert "suggestions" in result
        assert len(result["insights"]) > 0
        assert len(result["suggestions"]) > 0

    def test_parse_sections_with_overlapping_keywords(self) -> None:
        """Parser handles overlapping keywords correctly."""
        response = """
        Vulnerabilities:
        Security vulnerability detected in registration check.
        The security risk is moderate.

        Recommendations:
        Recommendation: add additional security layers.
        """

        section_keywords = {
            "vulnerabilities": ["vulnerability"],
            "recommendations": ["recommendation"],
            "risks": ["risk"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        assert all(key in result for key in section_keywords)
        assert len(result["vulnerabilities"]) > 0

    def test_parse_sections_with_empty_response(self) -> None:
        """Parser handles empty response without errors."""
        response = ""
        section_keywords = {"insights": ["vulnerability"], "suggestions": ["recommend"]}

        result = parse_ai_response_sections(response, section_keywords)

        assert result == {"insights": [], "suggestions": []}

    def test_parse_sections_with_no_matching_keywords(self) -> None:
        """Parser returns empty sections when no keywords match."""
        response = """
        This is some random text.
        No matching keywords here.
        Just generic content.
        """

        section_keywords = {
            "vulnerabilities": ["vulnerability", "exploit"],
            "recommendations": ["recommend", "suggest"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        assert result["vulnerabilities"] == []
        assert result["recommendations"] == []

    def test_parse_sections_with_malformed_response(self) -> None:
        """Parser handles malformed responses gracefully."""
        response = """
        Vulnerability Analysis:
        Line with vulnerability but incomplete


        Multiple blank lines

        Recommendations:
        Recommendation with    extra    spaces
        """

        section_keywords = {
            "vulnerabilities": ["vulnerability"],
            "recommendations": ["recommendations"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        assert isinstance(result, dict)
        assert all(isinstance(v, list) for v in result.values())

    def test_parse_sections_with_deeply_nested_structure(self) -> None:
        """Parser extracts content from complex nested structures."""
        response = """
        Vulnerability Analysis:
        Main vulnerability: License validation bypass
        Subpoint: Serial key algorithm weakness
        Detail: Uses weak MD5 hashing
        Subpoint: No server-side verification

        Recommendations:
        Primary recommendation: Implement RSA-2048 for serial generation
        Secondary: Add online activation
        Tertiary: Use HTTPS with certificate pinning
        """

        section_keywords = {
            "vulnerabilities": ["vulnerability"],
            "recommendations": ["recommendations"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        assert len(result["vulnerabilities"]) > 0
        assert len(result["recommendations"]) > 0
        assert any("MD5" in line for line in result["vulnerabilities"])
        assert any("RSA" in line for line in result["recommendations"])

    def test_parse_sections_with_case_insensitive_matching(self) -> None:
        """Parser performs case-insensitive keyword matching."""
        response = """
        VULNERABILITY:
        Critical buffer overflow
        VuLnErAbIlItY:
        Weak encryption
        vulnerability:
        Missing authorization
        """

        section_keywords = {"vulnerabilities": ["vulnerability"]}

        result = parse_ai_response_sections(response, section_keywords)

        assert len(result["vulnerabilities"]) >= 2

    def test_parse_sections_with_multiline_entries(self) -> None:
        """Parser handles multi-line section entries correctly."""
        response = """
        Vulnerability Assessment:
        Vulnerability found in license check routine
        Additional details about the vulnerability
        Impact assessment shows high severity

        Mitigation Recommendations:
        Recommendation for mitigation strategy
        Implementation requires code refactoring
        """

        section_keywords = {
            "vulnerabilities": ["vulnerability"],
            "recommendations": ["recommendation"],
        }

        result = parse_ai_response_sections(response, section_keywords)

        vuln_lines = result["vulnerabilities"]
        rec_lines = result["recommendations"]

        assert len(vuln_lines) > 0
        assert len(rec_lines) > 0


class TestParseSecurityAnalysisResponse:
    """Test security analysis response parsing."""

    def test_parse_security_analysis_standard_format(self) -> None:
        """Parser extracts insights and suggestions from standard security analysis."""
        response = """
        Security Analysis Results:

        Vulnerability Assessment:
        Critical vulnerability in license validation routine at offset 0x4012A0.
        Weak encryption scheme detected using XOR cipher.
        Risk of trivial bypass through binary patching.

        Recommendations:
        Recommend implementing stronger cryptographic algorithm (AES-256).
        Suggestion: add integrity checks using digital signatures.
        Should validate license on server-side.
        """

        insights, suggestions = parse_security_analysis_response(response)

        assert len(insights) > 0
        assert len(suggestions) > 0

    def test_parse_security_analysis_with_only_insights(self) -> None:
        """Parser handles response with only insights correctly."""
        response = """
        Vulnerability Analysis:
        Vulnerability: License check can be bypassed.
        Security issue: Weak serial validation.
        Risk level: High.
        """

        insights, suggestions = parse_security_analysis_response(response)

        assert len(insights) > 0
        assert len(suggestions) == 0

    def test_parse_security_analysis_with_only_suggestions(self) -> None:
        """Parser handles response with only suggestions correctly."""
        response = """
        Mitigation Strategy:
        Recommend strengthening license validation.
        Should implement hardware ID binding.
        Suggest using asymmetric cryptography.
        """

        insights, suggestions = parse_security_analysis_response(response)

        assert len(insights) == 0
        assert len(suggestions) > 0

    def test_parse_security_analysis_empty_response(self) -> None:
        """Parser handles empty security analysis response."""
        response = ""

        insights, suggestions = parse_security_analysis_response(response)

        assert insights == []
        assert suggestions == []

    def test_parse_security_analysis_with_mitigation_keywords(self) -> None:
        """Parser correctly identifies mitigation as suggestion."""
        response = """
        Security Assessment:
        Security weakness in trial reset logic.

        Mitigation Plan:
        Mitigation: Store trial data in encrypted registry keys.
        Fix: Implement server-side trial tracking.
        """

        insights, suggestions = parse_security_analysis_response(response)

        assert len(insights) > 0
        assert len(suggestions) > 0


class TestParseAttackVectorResponse:
    """Test attack vector response parsing."""

    def test_parse_attack_vector_complete_response(self) -> None:
        """Parser extracts vulnerabilities, recommendations, and attack vectors."""
        response = """
        Vulnerability Report:
        Vulnerability: License validation uses weak checksum.
        Security issue: No anti-debugging protection.

        Mitigation Recommendations:
        Recommendation: Implement VM-based protection.
        Suggest adding code obfuscation.

        Attack Vector Analysis:
        Attack vector: Patch jump at offset 0x401234.
        Exploit: Replace license check with NOP instructions.
        Payload: Keygen based on reverse-engineered algorithm.
        """

        vulnerabilities, recommendations, attack_vectors = parse_attack_vector_response(response)

        assert len(vulnerabilities) > 0
        assert len(recommendations) > 0
        assert len(attack_vectors) > 0

    def test_parse_attack_vector_with_missing_sections(self) -> None:
        """Parser handles response with missing sections."""
        response = """
        Vulnerability Analysis:
        Vulnerability: Trial period stored in plain text.

        Attack Methods:
        Attack: Modify registry value to reset trial.
        """

        vulnerabilities, recommendations, attack_vectors = parse_attack_vector_response(response)

        assert len(vulnerabilities) > 0
        assert len(attack_vectors) > 0
        assert len(recommendations) == 0

    def test_parse_attack_vector_empty_response(self) -> None:
        """Parser handles empty attack vector response."""
        response = ""

        vulnerabilities, recommendations, attack_vectors = parse_attack_vector_response(response)

        assert vulnerabilities == []
        assert recommendations == []
        assert attack_vectors == []

    def test_parse_attack_vector_with_overlapping_content(self) -> None:
        """Parser correctly categorizes overlapping content."""
        response = """
        Vulnerability Details:
        Vulnerability in attack surface: license server communication.

        Attack Analysis:
        Attack vector exploits this vulnerability.

        Security Recommendations:
        Recommendation: secure the attack surface.
        """

        vulnerabilities, recommendations, attack_vectors = parse_attack_vector_response(response)

        assert len(vulnerabilities) > 0
        assert len(recommendations) > 0
        assert len(attack_vectors) > 0


class TestParseSimpleResponse:
    """Test simple response parsing with custom keywords."""

    def test_parse_simple_with_default_keywords(self) -> None:
        """Parser uses default keywords when none provided."""
        response = """
        Findings:
        Risk of license bypass detected.
        Suspicious pattern in registration routine.
        Threat level: moderate.

        Recommendations:
        Recommend implementing additional validation.
        Should add server-side verification.
        Analyze the serial generation algorithm.
        """

        findings, recommendations = parse_simple_response(response)

        assert len(findings) > 0
        assert len(recommendations) > 0

    def test_parse_simple_with_custom_keywords(self) -> None:
        """Parser uses custom keywords when provided."""
        response = """
        Detected Issues:
        Detected weak license protection.
        Found trial reset vulnerability.

        Enhancements:
        Enhance protection with code obfuscation.
        Improve serial validation logic.
        """

        findings, recommendations = parse_simple_response(
            response,
            finding_keywords=["detected"],
            recommendation_keywords=["enhance"],
        )

        assert len(findings) > 0
        assert len(recommendations) > 0

    def test_parse_simple_empty_response(self) -> None:
        """Parser handles empty simple response."""
        response = ""

        findings, recommendations = parse_simple_response(response)

        assert findings == []
        assert recommendations == []

    def test_parse_simple_with_none_keywords(self) -> None:
        """Parser handles None keywords by using defaults."""
        response = """
        Analysis Results:
        Risk identified in license mechanism.

        Suggestions:
        Recommend strengthening protection.
        """

        findings, recommendations = parse_simple_response(
            response,
            finding_keywords=None,
            recommendation_keywords=None,
        )

        assert len(findings) > 0
        assert len(recommendations) > 0

    def test_parse_simple_with_no_matches(self) -> None:
        """Parser returns empty lists when keywords don't match."""
        response = """
        Generic text without matching keywords.
        More text that doesn't match.
        """

        findings, recommendations = parse_simple_response(
            response,
            finding_keywords=["specific", "unique"],
            recommendation_keywords=["particular", "distinct"],
        )

        assert findings == []
        assert recommendations == []

    def test_parse_simple_with_special_characters(self) -> None:
        """Parser handles responses with special characters."""
        response = """
        Risk Assessment:
        Risk: License bypass via 0x401234 -> 0x90909090 (NOP sled).
        Vulnerability: XOR(0xFF) encryption @ offset 0x3000.

        Mitigation:
        Recommend: Implement AES-256-GCM encryption.
        Should use RSA-4096 for key exchange.
        """

        findings, recommendations = parse_simple_response(response)

        assert len(findings) > 0
        assert len(recommendations) > 0
