"""
AI-Powered Automated Report Generation System for Intellicrack

This module provides comprehensive automated report generation with AI insights,
multi-format output support, and intelligent analysis synthesis.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import base64
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    from ...ai.llm_backends import get_llm_manager
    from ...ai.multi_agent_system import MultiAgentOrchestrator, AgentRole
    from ...ai.predictive_intelligence import PredictiveIntelligenceEngine
    AI_AVAILABLE = True
except ImportError as e:
    logger.warning(f"AI components not available: {e}")
    AI_AVAILABLE = False
    get_llm_manager = None
    MultiAgentOrchestrator = None
    AgentRole = None
    PredictiveIntelligenceEngine = None

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    logger.warning("Plotting libraries not available - charts will be skipped")
    PLOTTING_AVAILABLE = False
    plt = None
    sns = None

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    PDF_AVAILABLE = True
except ImportError:
    logger.warning("ReportLab not available - PDF generation will use fallback")
    PDF_AVAILABLE = False

try:
    import docx
    from docx import Document
    from docx.shared import Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    DOCX_AVAILABLE = True
except ImportError:
    logger.warning("python-docx not available - DOCX generation will be skipped")
    DOCX_AVAILABLE = False


class ReportType(Enum):
    """Types of reports that can be generated."""
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_ANALYSIS = "technical_analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    SECURITY_AUDIT = "security_audit"
    PENETRATION_TEST = "penetration_test"
    COMPLIANCE_REPORT = "compliance_report"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPREHENSIVE = "comprehensive"


class ReportFormat(Enum):
    """Supported report output formats."""
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"
    DOCX = "docx"
    TXT = "txt"


class ReportSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReportFinding:
    """Represents a security finding or analysis result."""
    id: str
    title: str
    description: str
    severity: ReportSeverity
    category: str
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 1.0
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    exploitation_difficulty: str = "Unknown"
    business_impact: str = "Unknown"
    ai_generated: bool = False
    ai_confidence: float = 0.0


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    report_id: str
    title: str
    report_type: ReportType
    target_binary: str
    generated_at: datetime
    generated_by: str = "Intellicrack AI Report Generator"
    version: str = "1.0"
    analysis_duration: Optional[timedelta] = None
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    ai_models_used: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)


@dataclass
class AIInsight:
    """AI-generated insight for the report."""
    insight_type: str
    title: str
    content: str
    confidence: float
    model_used: str
    generation_time: datetime = field(default_factory=datetime.now)
    supporting_evidence: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)


class AIReportGenerator:
    """
    Advanced AI-powered report generation system.
    
    Integrates with all AI components to generate comprehensive, intelligent
    security analysis reports with automated insights and recommendations.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize the AI report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # AI components
        self.llm_manager = get_llm_manager() if AI_AVAILABLE else None
        self.multi_agent = None
        self.predictive_engine = None
        
        # Report generation state
        self.current_findings: List[ReportFinding] = []
        self.ai_insights: List[AIInsight] = []
        self.report_metadata: Optional[ReportMetadata] = None
        self.analysis_context: Dict[str, Any] = {}
        
        # Templates and styles
        self.templates = self._load_report_templates()
        self.styles = self._initialize_styles()
        
        logger.info("AI Report Generator initialized")
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load report templates for different types."""
        return {
            ReportType.EXECUTIVE_SUMMARY.value: """
# Executive Summary

## Overview
{overview}

## Key Findings
{key_findings}

## Risk Assessment
{risk_assessment}

## Business Impact
{business_impact}

## Recommendations
{recommendations}
""",
            ReportType.TECHNICAL_ANALYSIS.value: """
# Technical Analysis Report

## Binary Information
{binary_info}

## Protection Mechanisms
{protection_analysis}

## Vulnerability Analysis
{vulnerability_analysis}

## Exploitation Assessment
{exploitation_assessment}

## Technical Recommendations
{technical_recommendations}

## Detailed Findings
{detailed_findings}
""",
            ReportType.COMPREHENSIVE.value: """
# Comprehensive Security Analysis Report

## Executive Summary
{executive_summary}

## Technical Overview
{technical_overview}

## Detailed Analysis
{detailed_analysis}

## AI-Generated Insights
{ai_insights}

## Risk Assessment
{risk_assessment}

## Mitigation Strategies
{mitigation_strategies}

## Future Recommendations
{future_recommendations}

## Appendices
{appendices}
"""
        }
    
    def _initialize_styles(self) -> Dict[str, Any]:
        """Initialize report styling configurations."""
        return {
            'html': {
                'header_color': '#2c3e50',
                'accent_color': '#3498db',
                'warning_color': '#e74c3c',
                'success_color': '#27ae60',
                'font_family': 'Arial, sans-serif',
                'font_size': '14px'
            },
            'pdf': {
                'page_size': A4 if PDF_AVAILABLE else None,
                'margin': 72,  # 1 inch
                'header_font_size': 18,
                'body_font_size': 12
            }
        }
    
    async def initialize_ai_components(self):
        """Initialize AI components for report generation."""
        if not AI_AVAILABLE:
            logger.warning("AI components not available - using fallback methods")
            return
        
        try:
            # Initialize multi-agent system
            self.multi_agent = MultiAgentOrchestrator()
            await self.multi_agent.initialize()
            
            # Initialize predictive intelligence
            self.predictive_engine = PredictiveIntelligenceEngine()
            await self.predictive_engine.initialize()
            
            logger.info("AI components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AI components: {e}")
            self.multi_agent = None
            self.predictive_engine = None
    
    def set_analysis_context(self, context: Dict[str, Any]):
        """Set the analysis context for report generation."""
        self.analysis_context = context
        logger.debug(f"Analysis context set with {len(context)} items")
    
    def add_finding(self, finding: ReportFinding):
        """Add a finding to the current report."""
        self.current_findings.append(finding)
        logger.debug(f"Added finding: {finding.title} ({finding.severity.value})")
    
    def add_ai_insight(self, insight: AIInsight):
        """Add an AI-generated insight to the report."""
        self.ai_insights.append(insight)
        logger.debug(f"Added AI insight: {insight.title}")
    
    async def generate_comprehensive_report(
        self,
        binary_path: str,
        report_type: ReportType = ReportType.COMPREHENSIVE,
        output_formats: List[ReportFormat] = None,
        include_ai_analysis: bool = True,
        include_predictive_insights: bool = True,
        custom_sections: List[str] = None
    ) -> Dict[str, str]:
        """
        Generate a comprehensive AI-powered report.
        
        Args:
            binary_path: Path to the analyzed binary
            report_type: Type of report to generate
            output_formats: List of output formats
            include_ai_analysis: Whether to include AI analysis
            include_predictive_insights: Whether to include predictive insights
            custom_sections: Custom sections to include
            
        Returns:
            Dict mapping format to output file path
        """
        if output_formats is None:
            output_formats = [ReportFormat.HTML, ReportFormat.PDF]
        
        start_time = datetime.now()
        report_id = str(uuid.uuid4())
        
        logger.info(f"Starting comprehensive report generation for {binary_path}")
        
        try:
            # Initialize metadata
            self._initialize_report_metadata(
                report_id, binary_path, report_type, start_time
            )
            
            # Collect analysis data
            await self._collect_analysis_data(binary_path)
            
            # Generate AI insights
            if include_ai_analysis and AI_AVAILABLE:
                await self._generate_ai_insights()
            
            # Generate predictive insights
            if include_predictive_insights and AI_AVAILABLE:
                await self._generate_predictive_insights()
            
            # Synthesize findings
            await self._synthesize_findings()
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary()
            
            # Generate risk assessment
            risk_assessment = await self._generate_risk_assessment()
            
            # Generate recommendations
            recommendations = await self._generate_recommendations()
            
            # Create report content
            report_content = await self._create_report_content(
                report_type, executive_summary, risk_assessment, 
                recommendations, custom_sections
            )
            
            # Generate outputs in requested formats
            output_files = {}
            for format_type in output_formats:
                output_path = await self._generate_format_output(
                    report_content, format_type, report_id
                )
                if output_path:
                    output_files[format_type.value] = output_path
            
            # Update metadata with completion info
            self.report_metadata.analysis_duration = datetime.now() - start_time
            self.report_metadata.total_findings = len(self.current_findings)
            self._update_finding_counts()
            
            logger.info(f"Report generation completed in {self.report_metadata.analysis_duration}")
            return output_files
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    def _initialize_report_metadata(
        self, 
        report_id: str, 
        binary_path: str, 
        report_type: ReportType, 
        start_time: datetime
    ):
        """Initialize report metadata."""
        self.report_metadata = ReportMetadata(
            report_id=report_id,
            title=f"Security Analysis Report - {Path(binary_path).name}",
            report_type=report_type,
            target_binary=binary_path,
            generated_at=start_time,
            data_sources=list(self.analysis_context.keys()) if self.analysis_context else []
        )
    
    async def _collect_analysis_data(self, binary_path: str):
        """Collect analysis data from various sources."""
        logger.info("Collecting analysis data from all sources")
        
        # Binary analysis data
        if 'binary_analysis' in self.analysis_context:
            await self._process_binary_analysis_data()
        
        # Protection analysis data
        if 'protection_analysis' in self.analysis_context:
            await self._process_protection_analysis_data()
        
        # Vulnerability data
        if 'vulnerability_analysis' in self.analysis_context:
            await self._process_vulnerability_data()
        
        # Network analysis data
        if 'network_analysis' in self.analysis_context:
            await self._process_network_analysis_data()
        
        # Memory analysis data
        if 'memory_analysis' in self.analysis_context:
            await self._process_memory_analysis_data()
        
        logger.info(f"Collected {len(self.current_findings)} findings from analysis data")
    
    async def _process_binary_analysis_data(self):
        """Process binary analysis data into findings."""
        binary_data = self.analysis_context.get('binary_analysis', {})
        
        # Extract architecture and platform info
        arch = binary_data.get('architecture', 'Unknown')
        platform = binary_data.get('platform', 'Unknown')
        
        # Check for suspicious characteristics
        if binary_data.get('packed', False):
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title="Packed Binary Detected",
                description=f"Binary appears to be packed using {binary_data.get('packer', 'unknown packer')}",
                severity=ReportSeverity.MEDIUM,
                category="Binary Analysis",
                evidence=[f"Packer detected: {binary_data.get('packer', 'Unknown')}"],
                recommendations=["Analyze unpacked binary for complete assessment"],
                confidence=binary_data.get('packer_confidence', 0.8)
            )
            self.add_finding(finding)
        
        # Check for anti-analysis features
        anti_analysis = binary_data.get('anti_analysis', [])
        if anti_analysis:
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title="Anti-Analysis Features Detected",
                description=f"Binary contains {len(anti_analysis)} anti-analysis techniques",
                severity=ReportSeverity.HIGH,
                category="Binary Analysis",
                evidence=[f"Detected techniques: {', '.join(anti_analysis)}"],
                recommendations=[
                    "Use anti-anti-analysis techniques during dynamic analysis",
                    "Consider specialized analysis environments"
                ],
                confidence=0.9
            )
            self.add_finding(finding)
    
    async def _process_protection_analysis_data(self):
        """Process protection analysis data into findings."""
        protection_data = self.analysis_context.get('protection_analysis', {})
        
        detected_protections = protection_data.get('detected_protections', [])
        for protection in detected_protections:
            severity = ReportSeverity.HIGH
            if protection.get('bypass_difficulty', 'high').lower() == 'low':
                severity = ReportSeverity.MEDIUM
            elif protection.get('bypass_difficulty', 'high').lower() == 'critical':
                severity = ReportSeverity.CRITICAL
            
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title=f"Protection Mechanism: {protection.get('name', 'Unknown')}",
                description=protection.get('description', 'Protection mechanism detected'),
                severity=severity,
                category="Protection Analysis",
                evidence=[
                    f"Detection confidence: {protection.get('confidence', 0.0):.1%}",
                    f"Bypass difficulty: {protection.get('bypass_difficulty', 'Unknown')}"
                ],
                recommendations=protection.get('bypass_strategies', []),
                confidence=protection.get('confidence', 0.0),
                exploitation_difficulty=protection.get('bypass_difficulty', 'Unknown')
            )
            self.add_finding(finding)
    
    async def _process_vulnerability_data(self):
        """Process vulnerability analysis data into findings."""
        vuln_data = self.analysis_context.get('vulnerability_analysis', {})
        
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title=vuln.get('title', 'Vulnerability Detected'),
                description=vuln.get('description', 'Security vulnerability identified'),
                severity=ReportSeverity(vuln.get('severity', 'medium')),
                category="Vulnerability Assessment",
                evidence=vuln.get('evidence', []),
                recommendations=vuln.get('recommendations', []),
                confidence=vuln.get('confidence', 0.0),
                cvss_score=vuln.get('cvss_score'),
                cve_ids=vuln.get('cve_ids', []),
                affected_components=vuln.get('affected_components', []),
                exploitation_difficulty=vuln.get('exploitation_difficulty', 'Unknown'),
                business_impact=vuln.get('business_impact', 'Unknown')
            )
            self.add_finding(finding)
    
    async def _process_network_analysis_data(self):
        """Process network analysis data into findings."""
        network_data = self.analysis_context.get('network_analysis', {})
        
        # Check for suspicious network behavior
        suspicious_connections = network_data.get('suspicious_connections', [])
        if suspicious_connections:
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title="Suspicious Network Activity",
                description=f"Detected {len(suspicious_connections)} suspicious network connections",
                severity=ReportSeverity.HIGH,
                category="Network Analysis",
                evidence=[f"Suspicious connections: {len(suspicious_connections)}"],
                recommendations=[
                    "Monitor network traffic during execution",
                    "Block suspicious IP addresses",
                    "Implement network segmentation"
                ],
                confidence=0.8
            )
            self.add_finding(finding)
        
        # Check for license server communications
        license_traffic = network_data.get('license_traffic', [])
        if license_traffic:
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title="License Server Communication",
                description="Binary communicates with license validation servers",
                severity=ReportSeverity.INFO,
                category="Network Analysis",
                evidence=[f"License servers: {len(license_traffic)}"],
                recommendations=[
                    "Analyze license validation protocol",
                    "Consider license server emulation",
                    "Monitor for authentication bypass opportunities"
                ],
                confidence=0.9
            )
            self.add_finding(finding)
    
    async def _process_memory_analysis_data(self):
        """Process memory analysis data into findings."""
        memory_data = self.analysis_context.get('memory_analysis', {})
        
        # Check for memory vulnerabilities
        memory_vulns = memory_data.get('memory_vulnerabilities', [])
        for vuln in memory_vulns:
            finding = ReportFinding(
                id=str(uuid.uuid4()),
                title=f"Memory Vulnerability: {vuln.get('type', 'Unknown')}",
                description=vuln.get('description', 'Memory-related vulnerability detected'),
                severity=ReportSeverity(vuln.get('severity', 'medium')),
                category="Memory Analysis",
                evidence=vuln.get('evidence', []),
                recommendations=vuln.get('recommendations', []),
                confidence=vuln.get('confidence', 0.0),
                exploitation_difficulty=vuln.get('exploitation_difficulty', 'Unknown')
            )
            self.add_finding(finding)
    
    async def _generate_ai_insights(self):
        """Generate AI-powered insights using the multi-agent system."""
        if not self.multi_agent:
            logger.warning("Multi-agent system not available for AI insights")
            return
        
        logger.info("Generating AI insights using multi-agent system")
        
        try:
            # Generate insights for different aspects
            aspects = [
                "protection_bypass_strategies",
                "vulnerability_prioritization", 
                "exploitation_feasibility",
                "business_impact_assessment",
                "mitigation_recommendations"
            ]
            
            for aspect in aspects:
                insight = await self._generate_aspect_insight(aspect)
                if insight:
                    self.add_ai_insight(insight)
            
            logger.info(f"Generated {len(self.ai_insights)} AI insights")
            
        except Exception as e:
            logger.error(f"Failed to generate AI insights: {e}")
    
    async def _generate_aspect_insight(self, aspect: str) -> Optional[AIInsight]:
        """Generate insight for a specific aspect."""
        if not self.llm_manager:
            return None
        
        prompt = self._create_insight_prompt(aspect)
        
        try:
            response = await self.llm_manager.generate_response(
                prompt=prompt,
                context=self.analysis_context,
                temperature=0.7,
                max_tokens=1000
            )
            
            if response and response.get('content'):
                return AIInsight(
                    insight_type=aspect,
                    title=self._get_aspect_title(aspect),
                    content=response['content'],
                    confidence=response.get('confidence', 0.8),
                    model_used=response.get('model', 'unknown'),
                    supporting_evidence=self._extract_evidence_from_findings(aspect),
                    related_findings=[f.id for f in self.current_findings if self._is_related_finding(f, aspect)]
                )
            
        except Exception as e:
            logger.error(f"Failed to generate insight for {aspect}: {e}")
            return None
    
    def _create_insight_prompt(self, aspect: str) -> str:
        """Create a prompt for generating insights on a specific aspect."""
        findings_summary = self._summarize_findings_for_prompt()
        
        prompts = {
            "protection_bypass_strategies": f"""
Based on the following security analysis findings, provide strategic recommendations for bypassing detected protection mechanisms:

{findings_summary}

Focus on:
1. Most effective bypass techniques
2. Tools and methods required
3. Potential challenges and solutions
4. Alternative approaches if primary methods fail

Provide practical, actionable strategies.
""",
            "vulnerability_prioritization": f"""
Based on the following vulnerability findings, provide a prioritization analysis:

{findings_summary}

Consider:
1. Exploitability and ease of exploitation
2. Business impact and data exposure risk
3. Likelihood of successful attack
4. Cost-benefit analysis for remediation

Rank vulnerabilities by remediation priority.
""",
            "exploitation_feasibility": f"""
Analyze the exploitation feasibility based on these findings:

{findings_summary}

Assess:
1. Technical complexity of exploitation
2. Required skills and resources
3. Success probability estimates
4. Detection likelihood during exploitation

Provide realistic feasibility assessment.
""",
            "business_impact_assessment": f"""
Evaluate the business impact of these security findings:

{findings_summary}

Consider:
1. Financial impact of successful exploitation
2. Reputational damage potential
3. Operational disruption risks
4. Regulatory compliance implications

Provide business-focused impact analysis.
""",
            "mitigation_recommendations": f"""
Provide comprehensive mitigation recommendations for these findings:

{findings_summary}

Include:
1. Immediate actions to reduce risk
2. Medium-term security improvements
3. Long-term strategic recommendations
4. Cost-effective prioritization approach

Focus on practical, implementable solutions.
"""
        }
        
        return prompts.get(aspect, f"Analyze the following findings for {aspect}:\n{findings_summary}")
    
    def _summarize_findings_for_prompt(self) -> str:
        """Create a summary of findings for AI prompt generation."""
        if not self.current_findings:
            return "No findings available for analysis."
        
        summary_lines = []
        for finding in self.current_findings:
            summary_lines.append(
                f"- {finding.title} ({finding.severity.value}): {finding.description}"
            )
        
        return "\n".join(summary_lines)
    
    def _get_aspect_title(self, aspect: str) -> str:
        """Get a human-readable title for an aspect."""
        titles = {
            "protection_bypass_strategies": "Protection Bypass Strategies",
            "vulnerability_prioritization": "Vulnerability Prioritization Analysis",
            "exploitation_feasibility": "Exploitation Feasibility Assessment",
            "business_impact_assessment": "Business Impact Analysis",
            "mitigation_recommendations": "Mitigation and Remediation Recommendations"
        }
        return titles.get(aspect, aspect.replace("_", " ").title())
    
    def _extract_evidence_from_findings(self, aspect: str) -> List[str]:
        """Extract relevant evidence from findings for an aspect."""
        evidence = []
        for finding in self.current_findings:
            if self._is_related_finding(finding, aspect):
                evidence.extend(finding.evidence)
        return evidence[:5]  # Limit to top 5 pieces of evidence
    
    def _is_related_finding(self, finding: ReportFinding, aspect: str) -> bool:
        """Check if a finding is related to a specific aspect."""
        aspect_keywords = {
            "protection_bypass_strategies": ["protection", "bypass", "anti-analysis"],
            "vulnerability_prioritization": ["vulnerability", "exploit", "security"],
            "exploitation_feasibility": ["exploit", "vulnerability", "attack"],
            "business_impact_assessment": ["impact", "risk", "business"],
            "mitigation_recommendations": ["mitigation", "recommendation", "fix"]
        }
        
        keywords = aspect_keywords.get(aspect, [])
        return any(keyword in finding.category.lower() or 
                  keyword in finding.title.lower() or 
                  keyword in finding.description.lower() 
                  for keyword in keywords)
    
    async def _generate_predictive_insights(self):
        """Generate predictive insights using the predictive intelligence engine."""
        if not self.predictive_engine:
            logger.warning("Predictive intelligence engine not available")
            return
        
        logger.info("Generating predictive intelligence insights")
        
        try:
            # Generate predictions for various scenarios
            predictions = await self.predictive_engine.generate_comprehensive_predictions(
                context=self.analysis_context,
                findings=self.current_findings
            )
            
            for prediction in predictions:
                insight = AIInsight(
                    insight_type="predictive_analysis",
                    title=f"Predictive Analysis: {prediction.get('scenario', 'Unknown')}",
                    content=prediction.get('analysis', ''),
                    confidence=prediction.get('confidence', 0.0),
                    model_used="predictive_intelligence_engine",
                    supporting_evidence=prediction.get('evidence', [])
                )
                self.add_ai_insight(insight)
            
            logger.info(f"Generated {len(predictions)} predictive insights")
            
        except Exception as e:
            logger.error(f"Failed to generate predictive insights: {e}")
    
    async def _synthesize_findings(self):
        """Synthesize and correlate findings to identify patterns."""
        logger.info("Synthesizing findings and identifying patterns")
        
        # Group findings by category
        categories = {}
        for finding in self.current_findings:
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(finding)
        
        # Identify cross-category patterns
        if len(categories) > 1:
            pattern_insight = await self._identify_cross_category_patterns(categories)
            if pattern_insight:
                self.add_ai_insight(pattern_insight)
        
        # Analyze severity distribution
        severity_analysis = self._analyze_severity_distribution()
        if severity_analysis:
            self.add_ai_insight(severity_analysis)
        
        # Identify attack chains
        attack_chains = self._identify_potential_attack_chains()
        if attack_chains:
            for chain in attack_chains:
                self.add_ai_insight(chain)
    
    async def _identify_cross_category_patterns(self, categories: Dict[str, List[ReportFinding]]) -> Optional[AIInsight]:
        """Identify patterns across different finding categories."""
        pattern_analysis = []
        
        # Look for common themes
        all_titles = [f.title for findings in categories.values() for f in findings]
        all_descriptions = [f.description for findings in categories.values() for f in findings]
        
        # Simple keyword analysis
        common_keywords = self._extract_common_keywords(all_titles + all_descriptions)
        
        if common_keywords:
            pattern_analysis.append(f"Common themes identified: {', '.join(common_keywords[:5])}")
        
        # Cross-reference high-severity findings
        high_severity_findings = [f for findings in categories.values() for f in findings 
                                if f.severity in [ReportSeverity.CRITICAL, ReportSeverity.HIGH]]
        
        if len(high_severity_findings) > 1:
            pattern_analysis.append(f"Multiple high-severity issues detected across {len(set(f.category for f in high_severity_findings))} categories")
        
        if pattern_analysis:
            return AIInsight(
                insight_type="pattern_analysis",
                title="Cross-Category Pattern Analysis",
                content="\n".join(pattern_analysis),
                confidence=0.7,
                model_used="pattern_analysis_engine",
                related_findings=[f.id for findings in categories.values() for f in findings]
            )
        
        return None
    
    def _extract_common_keywords(self, texts: List[str]) -> List[str]:
        """Extract common keywords from text list."""
        from collections import Counter
        
        # Simple keyword extraction
        all_words = []
        for text in texts:
            words = text.lower().split()
            all_words.extend([word.strip('.,!?();:') for word in words if len(word) > 3])
        
        # Get most common words
        word_counts = Counter(all_words)
        return [word for word, count in word_counts.most_common(10) if count > 1]
    
    def _analyze_severity_distribution(self) -> Optional[AIInsight]:
        """Analyze the distribution of finding severities."""
        if not self.current_findings:
            return None
        
        severity_counts = {}
        for finding in self.current_findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        total_findings = len(self.current_findings)
        
        analysis_lines = [
            f"Total findings: {total_findings}",
            "Severity distribution:"
        ]
        
        for severity in ReportSeverity:
            count = severity_counts.get(severity, 0)
            percentage = (count / total_findings) * 100
            analysis_lines.append(f"  {severity.value.title()}: {count} ({percentage:.1f}%)")
        
        # Risk assessment based on distribution
        critical_high_count = severity_counts.get(ReportSeverity.CRITICAL, 0) + severity_counts.get(ReportSeverity.HIGH, 0)
        risk_level = "Low"
        if critical_high_count > total_findings * 0.5:
            risk_level = "Critical"
        elif critical_high_count > total_findings * 0.3:
            risk_level = "High"
        elif critical_high_count > total_findings * 0.1:
            risk_level = "Medium"
        
        analysis_lines.append(f"\nOverall risk assessment: {risk_level}")
        
        return AIInsight(
            insight_type="severity_analysis",
            title="Severity Distribution Analysis",
            content="\n".join(analysis_lines),
            confidence=0.9,
            model_used="statistical_analysis_engine",
            related_findings=[f.id for f in self.current_findings]
        )
    
    def _identify_potential_attack_chains(self) -> List[AIInsight]:
        """Identify potential attack chains from findings."""
        attack_chains = []
        
        # Look for findings that could be chained together
        vulnerability_findings = [f for f in self.current_findings if "vulnerability" in f.category.lower()]
        protection_findings = [f for f in self.current_findings if "protection" in f.category.lower()]
        
        if vulnerability_findings and protection_findings:
            chain_analysis = [
                "Potential attack chain identified:",
                f"1. Bypass protection mechanisms ({len(protection_findings)} found)",
                f"2. Exploit vulnerabilities ({len(vulnerability_findings)} found)",
                "3. Escalate privileges or extract data"
            ]
            
            attack_chain_insight = AIInsight(
                insight_type="attack_chain",
                title="Potential Attack Chain Analysis",
                content="\n".join(chain_analysis),
                confidence=0.6,
                model_used="attack_chain_analyzer",
                related_findings=[f.id for f in vulnerability_findings + protection_findings]
            )
            attack_chains.append(attack_chain_insight)
        
        return attack_chains
    
    async def _generate_executive_summary(self) -> str:
        """Generate an AI-powered executive summary."""
        logger.info("Generating executive summary")
        
        if not self.llm_manager or not AI_AVAILABLE:
            return self._generate_fallback_executive_summary()
        
        try:
            summary_prompt = f"""
Generate a concise executive summary for a security analysis report with the following findings:

Total findings: {len(self.current_findings)}
Critical: {len([f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL])}
High: {len([f for f in self.current_findings if f.severity == ReportSeverity.HIGH])}
Medium: {len([f for f in self.current_findings if f.severity == ReportSeverity.MEDIUM])}
Low: {len([f for f in self.current_findings if f.severity == ReportSeverity.LOW])}

Key findings:
{self._summarize_findings_for_prompt()}

The summary should be suitable for executive stakeholders and focus on:
1. Overall security posture
2. Business impact of findings
3. Key risks that require immediate attention
4. High-level recommendations

Keep it concise but comprehensive (200-300 words).
"""
            
            response = await self.llm_manager.generate_response(
                prompt=summary_prompt,
                temperature=0.3,
                max_tokens=500
            )
            
            if response and response.get('content'):
                return response['content']
                
        except Exception as e:
            logger.error(f"Failed to generate AI executive summary: {e}")
        
        return self._generate_fallback_executive_summary()
    
    def _generate_fallback_executive_summary(self) -> str:
        """Generate a fallback executive summary without AI."""
        total_findings = len(self.current_findings)
        critical_count = len([f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL])
        high_count = len([f for f in self.current_findings if f.severity == ReportSeverity.HIGH])
        
        summary = f"""
This security analysis identified {total_findings} findings across multiple security domains. 
"""
        
        if critical_count > 0:
            summary += f"Of particular concern are {critical_count} critical-severity issues that require immediate attention. "
        
        if high_count > 0:
            summary += f"Additionally, {high_count} high-severity findings pose significant security risks. "
        
        if critical_count + high_count > 0:
            summary += "Priority should be given to addressing these high-impact vulnerabilities to reduce organizational risk exposure."
        else:
            summary += "The analysis indicates a relatively stable security posture with opportunities for incremental improvements."
        
        return summary
    
    async def _generate_risk_assessment(self) -> str:
        """Generate a comprehensive risk assessment."""
        logger.info("Generating risk assessment")
        
        if not self.llm_manager or not AI_AVAILABLE:
            return self._generate_fallback_risk_assessment()
        
        try:
            risk_prompt = f"""
Generate a comprehensive risk assessment based on these security findings:

{self._summarize_findings_for_prompt()}

Include:
1. Risk likelihood and impact analysis
2. Potential attack scenarios
3. Business continuity implications
4. Regulatory compliance risks
5. Overall risk rating (Critical/High/Medium/Low)

Focus on quantifiable risks and business impact.
"""
            
            response = await self.llm_manager.generate_response(
                prompt=risk_prompt,
                temperature=0.3,
                max_tokens=800
            )
            
            if response and response.get('content'):
                return response['content']
                
        except Exception as e:
            logger.error(f"Failed to generate AI risk assessment: {e}")
        
        return self._generate_fallback_risk_assessment()
    
    def _generate_fallback_risk_assessment(self) -> str:
        """Generate a fallback risk assessment without AI."""
        total_findings = len(self.current_findings)
        critical_count = len([f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL])
        high_count = len([f for f in self.current_findings if f.severity == ReportSeverity.HIGH])
        medium_count = len([f for f in self.current_findings if f.severity == ReportSeverity.MEDIUM])
        
        risk_score = (critical_count * 4) + (high_count * 3) + (medium_count * 2)
        
        if risk_score >= 15:
            risk_level = "Critical"
        elif risk_score >= 10:
            risk_level = "High"
        elif risk_score >= 5:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        assessment = f"""
Risk Assessment Summary:

Overall Risk Level: {risk_level}
Risk Score: {risk_score}/20

Key Risk Factors:
- {critical_count} critical vulnerabilities requiring immediate remediation
- {high_count} high-severity issues with significant impact potential
- {medium_count} medium-severity findings requiring planned remediation

Business Impact Considerations:
- Potential for unauthorized access and data exposure
- Possible service disruption from successful attacks
- Regulatory compliance implications
- Reputational damage from security incidents
"""
        
        return assessment
    
    async def _generate_recommendations(self) -> str:
        """Generate comprehensive recommendations."""
        logger.info("Generating recommendations")
        
        if not self.llm_manager or not AI_AVAILABLE:
            return self._generate_fallback_recommendations()
        
        try:
            recommendations_prompt = f"""
Generate prioritized security recommendations based on these findings:

{self._summarize_findings_for_prompt()}

Provide:
1. Immediate actions (0-30 days)
2. Short-term improvements (1-3 months)
3. Long-term strategic initiatives (6+ months)
4. Budget and resource considerations
5. Success metrics for each recommendation

Focus on practical, implementable solutions.
"""
            
            response = await self.llm_manager.generate_response(
                prompt=recommendations_prompt,
                temperature=0.4,
                max_tokens=1000
            )
            
            if response and response.get('content'):
                return response['content']
                
        except Exception as e:
            logger.error(f"Failed to generate AI recommendations: {e}")
        
        return self._generate_fallback_recommendations()
    
    def _generate_fallback_recommendations(self) -> str:
        """Generate fallback recommendations without AI."""
        critical_findings = [f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL]
        high_findings = [f for f in self.current_findings if f.severity == ReportSeverity.HIGH]
        
        recommendations = "Security Recommendations:\n\n"
        
        if critical_findings:
            recommendations += "IMMEDIATE ACTIONS (0-7 days):\n"
            for finding in critical_findings[:3]:  # Top 3 critical
                for rec in finding.recommendations[:2]:  # Top 2 recommendations per finding
                    recommendations += f"• {rec}\n"
            recommendations += "\n"
        
        if high_findings:
            recommendations += "SHORT-TERM ACTIONS (1-4 weeks):\n"
            for finding in high_findings[:3]:  # Top 3 high
                for rec in finding.recommendations[:1]:  # Top recommendation per finding
                    recommendations += f"• {rec}\n"
            recommendations += "\n"
        
        recommendations += "GENERAL RECOMMENDATIONS:\n"
        recommendations += "• Implement regular security assessments\n"
        recommendations += "• Establish incident response procedures\n"
        recommendations += "• Provide security awareness training\n"
        recommendations += "• Monitor for emerging threats and vulnerabilities\n"
        
        return recommendations
    
    async def _create_report_content(
        self,
        report_type: ReportType,
        executive_summary: str,
        risk_assessment: str,
        recommendations: str,
        custom_sections: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create the complete report content structure."""
        logger.info(f"Creating {report_type.value} report content")
        
        content = {
            'metadata': self.report_metadata,
            'executive_summary': executive_summary,
            'risk_assessment': risk_assessment,
            'recommendations': recommendations,
            'findings': self.current_findings,
            'ai_insights': self.ai_insights,
            'analysis_context': self.analysis_context
        }
        
        # Add type-specific sections
        if report_type == ReportType.TECHNICAL_ANALYSIS:
            content.update(await self._create_technical_sections())
        elif report_type == ReportType.VULNERABILITY_ASSESSMENT:
            content.update(await self._create_vulnerability_sections())
        elif report_type == ReportType.COMPREHENSIVE:
            content.update(await self._create_comprehensive_sections())
        
        # Add custom sections if specified
        if custom_sections:
            content['custom_sections'] = await self._create_custom_sections(custom_sections)
        
        return content
    
    async def _create_technical_sections(self) -> Dict[str, Any]:
        """Create technical analysis specific sections."""
        return {
            'binary_analysis': self.analysis_context.get('binary_analysis', {}),
            'protection_analysis': self.analysis_context.get('protection_analysis', {}),
            'memory_analysis': self.analysis_context.get('memory_analysis', {}),
            'network_analysis': self.analysis_context.get('network_analysis', {})
        }
    
    async def _create_vulnerability_sections(self) -> Dict[str, Any]:
        """Create vulnerability assessment specific sections."""
        vulnerability_findings = [f for f in self.current_findings if 'vulnerability' in f.category.lower()]
        
        return {
            'vulnerability_summary': {
                'total_vulnerabilities': len(vulnerability_findings),
                'critical_vulnerabilities': len([f for f in vulnerability_findings if f.severity == ReportSeverity.CRITICAL]),
                'exploitable_vulnerabilities': len([f for f in vulnerability_findings if f.exploitation_difficulty in ['Low', 'Medium']])
            },
            'vulnerability_details': vulnerability_findings,
            'exploitation_assessment': await self._create_exploitation_assessment(vulnerability_findings)
        }
    
    async def _create_comprehensive_sections(self) -> Dict[str, Any]:
        """Create comprehensive report sections."""
        return {
            'analysis_overview': await self._create_analysis_overview(),
            'findings_summary': await self._create_findings_summary(),
            'security_posture': await self._create_security_posture_assessment(),
            'threat_landscape': await self._create_threat_landscape_analysis(),
            'compliance_assessment': await self._create_compliance_assessment()
        }
    
    async def _create_analysis_overview(self) -> Dict[str, Any]:
        """Create analysis overview section."""
        return {
            'scope': f"Comprehensive security analysis of {self.report_metadata.target_binary}",
            'methodology': "Multi-layered analysis including static, dynamic, and AI-powered assessment",
            'tools_used': list(self.analysis_context.keys()),
            'analysis_duration': str(self.report_metadata.analysis_duration) if self.report_metadata.analysis_duration else "Unknown",
            'coverage_areas': list(set(f.category for f in self.current_findings))
        }
    
    async def _create_findings_summary(self) -> Dict[str, Any]:
        """Create findings summary section."""
        findings_by_category = {}
        for finding in self.current_findings:
            if finding.category not in findings_by_category:
                findings_by_category[finding.category] = []
            findings_by_category[finding.category].append(finding)
        
        return {
            'total_findings': len(self.current_findings),
            'findings_by_category': {
                category: len(findings) for category, findings in findings_by_category.items()
            },
            'findings_by_severity': {
                severity.value: len([f for f in self.current_findings if f.severity == severity])
                for severity in ReportSeverity
            },
            'top_findings': sorted(self.current_findings, 
                                 key=lambda f: (f.severity.value, -f.confidence))[:10]
        }
    
    async def _create_security_posture_assessment(self) -> Dict[str, Any]:
        """Create security posture assessment."""
        critical_count = len([f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL])
        high_count = len([f for f in self.current_findings if f.severity == ReportSeverity.HIGH])
        
        posture_score = max(0, 100 - (critical_count * 25) - (high_count * 10))
        
        if posture_score >= 90:
            posture_level = "Excellent"
        elif posture_score >= 75:
            posture_level = "Good"
        elif posture_score >= 60:
            posture_level = "Fair"
        elif posture_score >= 40:
            posture_level = "Poor"
        else:
            posture_level = "Critical"
        
        return {
            'overall_score': posture_score,
            'posture_level': posture_level,
            'strengths': await self._identify_security_strengths(),
            'weaknesses': await self._identify_security_weaknesses(),
            'improvement_areas': await self._identify_improvement_areas()
        }
    
    async def _identify_security_strengths(self) -> List[str]:
        """Identify security strengths."""
        strengths = []
        
        # Check for strong protections
        protection_findings = [f for f in self.current_findings if 'protection' in f.category.lower()]
        if protection_findings:
            strengths.append(f"Multiple protection mechanisms detected ({len(protection_findings)})")
        
        # Check for low vulnerability count
        vuln_findings = [f for f in self.current_findings if 'vulnerability' in f.category.lower()]
        if len(vuln_findings) < 5:
            strengths.append("Relatively low vulnerability count")
        
        # Default strength if none identified
        if not strengths:
            strengths.append("Analysis completed successfully with comprehensive coverage")
        
        return strengths
    
    async def _identify_security_weaknesses(self) -> List[str]:
        """Identify security weaknesses."""
        weaknesses = []
        
        critical_findings = [f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL]
        if critical_findings:
            weaknesses.append(f"Critical security vulnerabilities present ({len(critical_findings)})")
        
        high_findings = [f for f in self.current_findings if f.severity == ReportSeverity.HIGH]
        if high_findings:
            weaknesses.append(f"High-severity security issues identified ({len(high_findings)})")
        
        # Check for specific weakness patterns
        for finding in self.current_findings:
            if 'bypass' in finding.title.lower():
                weaknesses.append("Protection bypass opportunities identified")
                break
        
        return weaknesses
    
    async def _identify_improvement_areas(self) -> List[str]:
        """Identify areas for security improvement."""
        improvements = []
        
        # Generic improvements based on findings
        if [f for f in self.current_findings if f.severity in [ReportSeverity.CRITICAL, ReportSeverity.HIGH]]:
            improvements.append("Implement additional security controls")
            improvements.append("Enhance vulnerability management processes")
        
        improvements.append("Regular security assessments and monitoring")
        improvements.append("Security awareness and training programs")
        
        return improvements
    
    async def _create_threat_landscape_analysis(self) -> Dict[str, Any]:
        """Create threat landscape analysis."""
        return {
            'threat_actors': ['Advanced Persistent Threats', 'Script Kiddies', 'Insider Threats'],
            'attack_vectors': ['Network-based attacks', 'Local exploitation', 'Social engineering'],
            'trending_threats': ['Zero-day exploits', 'Supply chain attacks', 'AI-powered attacks'],
            'industry_context': 'Threats targeting similar software and platforms'
        }
    
    async def _create_compliance_assessment(self) -> Dict[str, Any]:
        """Create compliance assessment section."""
        return {
            'frameworks_assessed': ['NIST Cybersecurity Framework', 'ISO 27001', 'CIS Controls'],
            'compliance_gaps': await self._identify_compliance_gaps(),
            'recommendations': [
                'Implement security control monitoring',
                'Establish incident response procedures',
                'Conduct regular compliance audits'
            ]
        }
    
    async def _identify_compliance_gaps(self) -> List[str]:
        """Identify compliance gaps based on findings."""
        gaps = []
        
        if [f for f in self.current_findings if f.severity == ReportSeverity.CRITICAL]:
            gaps.append("Critical vulnerabilities present - requires immediate remediation")
        
        if not any('monitoring' in f.title.lower() for f in self.current_findings):
            gaps.append("Insufficient security monitoring capabilities")
        
        gaps.append("Regular vulnerability assessments needed")
        
        return gaps
    
    async def _create_exploitation_assessment(self, vulnerability_findings: List[ReportFinding]) -> Dict[str, Any]:
        """Create exploitation assessment for vulnerabilities."""
        return {
            'exploitable_count': len([f for f in vulnerability_findings if f.exploitation_difficulty in ['Low', 'Medium']]),
            'exploitation_scenarios': await self._create_exploitation_scenarios(vulnerability_findings),
            'mitigation_priority': sorted(vulnerability_findings, 
                                        key=lambda f: (f.severity.value, f.exploitation_difficulty))[:5]
        }
    
    async def _create_exploitation_scenarios(self, vulnerability_findings: List[ReportFinding]) -> List[Dict[str, Any]]:
        """Create exploitation scenarios for vulnerabilities."""
        scenarios = []
        
        for finding in vulnerability_findings[:3]:  # Top 3 vulnerabilities
            scenario = {
                'vulnerability': finding.title,
                'attack_vector': 'Multiple vectors possible',
                'prerequisites': 'Basic to intermediate technical skills',
                'impact': finding.business_impact,
                'likelihood': 'Medium to High' if finding.exploitation_difficulty in ['Low', 'Medium'] else 'Low'
            }
            scenarios.append(scenario)
        
        return scenarios
    
    async def _create_custom_sections(self, custom_sections: List[str]) -> Dict[str, Any]:
        """Create custom report sections."""
        sections = {}
        
        for section_name in custom_sections:
            sections[section_name] = {
                'title': section_name,
                'content': f"Custom section: {section_name}",
                'generated_at': datetime.now().isoformat()
            }
        
        return sections
    
    def _update_finding_counts(self):
        """Update finding counts in metadata."""
        if not self.report_metadata:
            return
        
        severity_counts = {severity: 0 for severity in ReportSeverity}
        for finding in self.current_findings:
            severity_counts[finding.severity] += 1
        
        self.report_metadata.critical_findings = severity_counts[ReportSeverity.CRITICAL]
        self.report_metadata.high_findings = severity_counts[ReportSeverity.HIGH]
        self.report_metadata.medium_findings = severity_counts[ReportSeverity.MEDIUM]
        self.report_metadata.low_findings = severity_counts[ReportSeverity.LOW]
        self.report_metadata.info_findings = severity_counts[ReportSeverity.INFO]