#!/usr/bin/env python3
"""
Advanced Export Options - Comprehensive reporting system for CLI

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

import csv
import json
import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List

# Optional imports for enhanced export capabilities
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import xlsxwriter
    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False


class AdvancedExporter:
    """Advanced export system with multiple formats and detailed reporting."""

    def __init__(self, binary_path: str, analysis_results: Dict[str, Any]):
        """Initialize exporter with analysis data.

        Args:
            binary_path: Path to analyzed binary
            analysis_results: Dictionary of analysis results
        """
        self.binary_path = binary_path
        self.analysis_results = analysis_results
        self.logger = logging.getLogger(__name__)
        self.export_metadata = {
            'export_time': datetime.now().isoformat(),
            'binary_path': binary_path,
            'binary_name': os.path.basename(binary_path),
            'export_version': '2.0',
            'tool': 'Intellicrack CLI'
        }

    def export_detailed_json(self, output_path: str, include_raw_data: bool = True) -> bool:
        """Export detailed JSON with metadata and structured analysis results.

        Args:
            output_path: Output file path
            include_raw_data: Whether to include raw binary data excerpts

        Returns:
            True if export successful
        """
        try:
            export_data = {
                'metadata': self.export_metadata,
                'summary': self._generate_summary(),
                'analysis_results': self.analysis_results,
                'statistics': self._generate_statistics(),
                'recommendations': self._generate_recommendations()
            }

            if include_raw_data:
                export_data['raw_data_samples'] = self._extract_raw_data_samples()

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)

            return True
        except Exception as e:
            print(f"JSON export failed: {e}")
            return False

    def export_executive_summary(self, output_path: str, format_type: str = 'markdown') -> bool:
        """Export executive summary in various formats.

        Args:
            output_path: Output file path
            format_type: Format (markdown, html, txt)

        Returns:
            True if export successful
        """
        summary_data = self._generate_executive_summary()

        try:
            if format_type.lower() == 'markdown':
                return self._export_markdown_summary(output_path, summary_data)
            elif format_type.lower() == 'html':
                return self._export_html_summary(output_path, summary_data)
            elif format_type.lower() == 'txt':
                return self._export_text_summary(output_path, summary_data)
            else:
                print(f"Unsupported format: {format_type}")
                return False
        except Exception as e:
            print(f"Executive summary export failed: {e}")
            return False

    def export_vulnerability_report(self, output_path: str) -> bool:
        """Export detailed vulnerability report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful
        """
        try:
            vuln_data = self.analysis_results.get('vulnerabilities', {})

            report = {
                'metadata': self.export_metadata,
                'executive_summary': {
                    'total_vulnerabilities': len(vuln_data.get('vulnerabilities', [])),
                    'critical_count': self._count_vulnerabilities_by_severity(vuln_data, 'critical'),
                    'high_count': self._count_vulnerabilities_by_severity(vuln_data, 'high'),
                    'medium_count': self._count_vulnerabilities_by_severity(vuln_data, 'medium'),
                    'low_count': self._count_vulnerabilities_by_severity(vuln_data, 'low'),
                    'risk_score': self._calculate_risk_score(vuln_data)
                },
                'detailed_findings': self._format_vulnerability_details(vuln_data),
                'mitigation_strategies': self._generate_mitigation_strategies(vuln_data),
                'compliance_notes': self._generate_compliance_notes(vuln_data)
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str, ensure_ascii=False)

            return True
        except Exception as e:
            print(f"Vulnerability report export failed: {e}")
            return False

    def export_csv_data(self, output_path: str, data_type: str = 'all') -> bool:
        """Export analysis data in CSV format.

        Args:
            output_path: Output file path
            data_type: Type of data to export (all, vulnerabilities, strings, imports)

        Returns:
            True if export successful
        """
        try:
            if data_type == 'vulnerabilities':
                return self._export_vulnerabilities_csv(output_path)
            elif data_type == 'strings':
                return self._export_strings_csv(self.analysis_results.get('strings', []), output_path)
            elif data_type == 'imports':
                return self._export_imports_csv(self.analysis_results.get('imports', []), output_path)
            elif data_type == 'all':
                return self._export_comprehensive_csv(self.analysis_results, output_path)
            else:
                print(f"Unsupported CSV data type: {data_type}")
                return False
        except Exception as e:
            print(f"CSV export failed: {e}")
            return False

    def export_xml_report(self, output_path: str) -> bool:
        """Export structured XML report.

        Args:
            output_path: Output file path

        Returns:
            True if export successful
        """
        try:
            root = ET.Element("intellicrack_report")

            # Metadata
            metadata_elem = ET.SubElement(root, "metadata")
            for key, value in self.export_metadata.items():
                elem = ET.SubElement(metadata_elem, key.replace(' ', '_'))
                elem.text = str(value)

            # Analysis results
            analysis_elem = ET.SubElement(root, "analysis_results")
            self._dict_to_xml(self.analysis_results, analysis_elem)

            # Summary
            summary_elem = ET.SubElement(root, "summary")
            summary_data = self._generate_summary()
            self._dict_to_xml(summary_data, summary_elem)

            # Write XML
            tree = ET.ElementTree(root)
            ET.indent(tree, space="  ", level=0)
            tree.write(output_path, encoding='utf-8', xml_declaration=True)

            return True
        except Exception as e:
            print(f"XML export failed: {e}")
            return False

    def export_yaml_config(self, output_path: str) -> bool:
        """Export analysis results as YAML configuration.

        Args:
            output_path: Output file path

        Returns:
            True if export successful
        """
        if not YAML_AVAILABLE:
            print("YAML export not available. Install PyYAML: pip install PyYAML")
            return False

        try:
            export_data = {
                'metadata': self.export_metadata,
                'analysis_config': self._generate_analysis_config(),
                'findings_summary': self._generate_summary(),
                'detection_rules': self._generate_detection_rules()
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(export_data, f, default_flow_style=False, allow_unicode=True)

            return True
        except Exception as e:
            print(f"YAML export failed: {e}")
            return False

    def export_excel_workbook(self, output_path: str) -> bool:
        """Export comprehensive Excel workbook with multiple sheets.

        Args:
            output_path: Output file path

        Returns:
            True if export successful
        """
        if not XLSX_AVAILABLE:
            print("Excel export not available. Install xlsxwriter: pip install xlsxwriter")
            return False

        try:
            workbook = xlsxwriter.Workbook(output_path)

            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#4472C4',
                'font_color': 'white',
                'border': 1
            })

            cell_format = workbook.add_format({'border': 1})

            # Summary sheet
            self._create_summary_sheet(workbook, header_format, cell_format)

            # Vulnerabilities sheet
            self._create_vulnerabilities_sheet(workbook, header_format, cell_format)

            # Strings sheet
            self._create_strings_sheet(workbook, header_format, cell_format)

            # Imports sheet
            self._create_imports_sheet(workbook, header_format, cell_format)

            # Statistics sheet
            self._create_statistics_sheet(workbook, header_format, cell_format)

            workbook.close()
            return True
        except Exception as e:
            print(f"Excel export failed: {e}")
            return False

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary."""
        summary = {
            'file_info': {
                'name': os.path.basename(self.binary_path),
                'path': self.binary_path,
                'size': os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0
            },
            'analysis_overview': {},
            'key_findings': [],
            'security_assessment': {}
        }

        # Count different analysis types
        for analysis_type, results in self.analysis_results.items():
            if isinstance(results, dict):
                summary['analysis_overview'][analysis_type] = len(results)
            elif isinstance(results, list):
                summary['analysis_overview'][analysis_type] = len(results)
            else:
                summary['analysis_overview'][analysis_type] = 1

        # Extract key findings
        if 'vulnerabilities' in self.analysis_results:
            vuln_data = self.analysis_results['vulnerabilities']
            if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
                vuln_count = len(vuln_data['vulnerabilities'])
                if vuln_count > 0:
                    summary['key_findings'].append(f"{vuln_count} potential vulnerabilities detected")

        if 'protections' in self.analysis_results:
            prot_data = self.analysis_results['protections']
            if isinstance(prot_data, dict):
                enabled_protections = [k for k, v in prot_data.items() if v]
                if enabled_protections:
                    summary['key_findings'].append(f"Security protections: {', '.join(enabled_protections)}")

        return summary

    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate analysis statistics."""
        stats = {
            'analysis_time': self.export_metadata['export_time'],
            'total_categories': len(self.analysis_results),
            'data_points': 0,
            'categories': {}
        }

        for category, data in self.analysis_results.items():
            if isinstance(data, dict):
                count = len(data)
            elif isinstance(data, list):
                count = len(data)
            else:
                count = 1

            stats['categories'][category] = count
            stats['data_points'] += count

        return stats

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []

        # Check for vulnerabilities
        vuln_data = self.analysis_results.get('vulnerabilities', {})
        if isinstance(vuln_data, dict) and vuln_data.get('vulnerabilities'):
            recommendations.append("Address identified vulnerabilities before deployment")
            recommendations.append("Implement input validation and bounds checking")

        # Check for protections
        prot_data = self.analysis_results.get('protections', {})
        if isinstance(prot_data, dict):
            if not prot_data.get('aslr', True):
                recommendations.append("Enable ASLR (Address Space Layout Randomization)")
            if not prot_data.get('dep', True):
                recommendations.append("Enable DEP/NX (Data Execution Prevention)")
            if not prot_data.get('canary', True):
                recommendations.append("Enable stack canaries for buffer overflow protection")

        # General recommendations
        recommendations.extend([
            "Regular security audits and penetration testing",
            "Keep all dependencies and libraries updated",
            "Implement proper error handling and logging",
            "Use secure coding practices and code reviews"
        ])

        return recommendations

    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary data."""
        return {
            'title': f"Security Analysis Report: {os.path.basename(self.binary_path)}",
            'analysis_date': self.export_metadata['export_time'],
            'binary_info': {
                'name': os.path.basename(self.binary_path),
                'size': os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0
            },
            'risk_assessment': self._assess_overall_risk(),
            'key_findings': self._extract_key_findings(),
            'recommendations': self._generate_recommendations()[:5],  # Top 5
            'next_steps': [
                "Review and address critical vulnerabilities",
                "Implement recommended security controls",
                "Conduct follow-up testing after remediation"
            ]
        }

    def _export_markdown_summary(self, output_path: str, summary_data: Dict[str, Any]) -> bool:
        """Export executive summary as Markdown."""
        content = f"""# {summary_data['title']}

**Analysis Date:** {summary_data['analysis_date']}

## Binary Information
- **Name:** {summary_data['binary_info']['name']}
- **Size:** {summary_data['binary_info']['size']:,} bytes

## Risk Assessment
**Overall Risk:** {summary_data['risk_assessment']['level']}

{summary_data['risk_assessment']['description']}

## Key Findings
"""

        for finding in summary_data['key_findings']:
            content += f"- {finding}\n"

        content += "\n## Recommendations\n"
        for i, rec in enumerate(summary_data['recommendations'], 1):
            content += f"{i}. {rec}\n"

        content += "\n## Next Steps\n"
        for step in summary_data['next_steps']:
            content += f"- {step}\n"

        content += f"\n---\n*Generated by Intellicrack CLI v{self.export_metadata['export_version']}*\n"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return True

    def _export_html_summary(self, output_path: str, summary_data: Dict[str, Any]) -> bool:
        """Export executive summary as HTML."""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .risk-high {{ color: #d9534f; }}
        .risk-medium {{ color: #f0ad4e; }}
        .risk-low {{ color: #5cb85c; }}
        .findings {{ background-color: #f9f9f9; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p><strong>Analysis Date:</strong> {analysis_date}</p>
    </div>

    <h2>Binary Information</h2>
    <ul>
        <li><strong>Name:</strong> {binary_name}</li>
        <li><strong>Size:</strong> {binary_size:,} bytes</li>
    </ul>

    <h2>Risk Assessment</h2>
    <p class="risk-{risk_class}"><strong>Overall Risk:</strong> {risk_level}</p>
    <p>{risk_description}</p>

    <h2>Key Findings</h2>
    <div class="findings">
        <ul>
            {findings_list}
        </ul>
    </div>

    <h2>Recommendations</h2>
    <ol>
        {recommendations_list}
    </ol>

    <hr>
    <p><em>Generated by Intellicrack CLI v{version}</em></p>
</body>
</html>"""

        findings_html = "".join(f"<li>{finding}</li>" for finding in summary_data['key_findings'])
        recommendations_html = "".join(f"<li>{rec}</li>" for rec in summary_data['recommendations'])

        risk_level = summary_data['risk_assessment']['level']
        risk_class = risk_level.lower() if risk_level.lower() in ['high', 'medium', 'low'] else 'medium'

        html_content = html_template.format(
            title=summary_data['title'],
            analysis_date=summary_data['analysis_date'],
            binary_name=summary_data['binary_info']['name'],
            binary_size=summary_data['binary_info']['size'],
            risk_level=risk_level,
            risk_class=risk_class,
            risk_description=summary_data['risk_assessment']['description'],
            findings_list=findings_html,
            recommendations_list=recommendations_html,
            version=self.export_metadata['export_version']
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return True

    def _export_text_summary(self, output_path: str, summary_data: Dict[str, Any]) -> bool:
        """Export executive summary as plain text."""
        content = f"""{summary_data['title']}
{'=' * len(summary_data['title'])}

Analysis Date: {summary_data['analysis_date']}

BINARY INFORMATION
------------------
Name: {summary_data['binary_info']['name']}
Size: {summary_data['binary_info']['size']:,} bytes

RISK ASSESSMENT
---------------
Overall Risk: {summary_data['risk_assessment']['level']}

{summary_data['risk_assessment']['description']}

KEY FINDINGS
------------
"""

        for finding in summary_data['key_findings']:
            content += f"• {finding}\n"

        content += "\nRECOMMENDATIONS\n---------------\n"
        for i, rec in enumerate(summary_data['recommendations'], 1):
            content += f"{i}. {rec}\n"

        content += f"\n\nGenerated by Intellicrack CLI v{self.export_metadata['export_version']}\n"

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return True

    def _assess_overall_risk(self) -> Dict[str, str]:
        """Assess overall security risk."""
        vuln_data = self.analysis_results.get('vulnerabilities', {})

        if isinstance(vuln_data, dict):
            vulns = vuln_data.get('vulnerabilities', [])
            critical_count = self._count_vulnerabilities_by_severity(vuln_data, 'critical')
            high_count = self._count_vulnerabilities_by_severity(vuln_data, 'high')

            if critical_count > 0:
                return {
                    'level': 'HIGH',
                    'description': f"Critical vulnerabilities detected ({critical_count} critical, {high_count} high severity). Immediate action required."
                }
            elif high_count > 2:
                return {
                    'level': 'MEDIUM',
                    'description': f"Multiple high-severity vulnerabilities detected ({high_count}). Prompt remediation recommended."
                }
            elif len(vulns) > 0:
                return {
                    'level': 'LOW',
                    'description': f"Some vulnerabilities detected ({len(vulns)} total). Review and address as appropriate."
                }

        return {
            'level': 'LOW',
            'description': "No critical vulnerabilities detected. Continue monitoring and regular assessments."
        }

    def _extract_key_findings(self) -> List[str]:
        """Extract key findings from analysis results."""
        findings = []

        # Vulnerability findings
        vuln_data = self.analysis_results.get('vulnerabilities', {})
        if isinstance(vuln_data, dict):
            vulns = vuln_data.get('vulnerabilities', [])
            if vulns:
                findings.append(f"{len(vulns)} potential vulnerabilities identified")

        # Protection findings
        prot_data = self.analysis_results.get('protections', {})
        if isinstance(prot_data, dict):
            missing_protections = [k for k, v in prot_data.items() if not v]
            if missing_protections:
                findings.append(f"Missing security protections: {', '.join(missing_protections)}")

        # String analysis findings
        strings_data = self.analysis_results.get('strings', [])
        if isinstance(strings_data, list) and len(strings_data) > 100:
            findings.append(f"Large number of embedded strings detected ({len(strings_data)})")

        return findings

    def _count_vulnerabilities_by_severity(self, vuln_data: Dict[str, Any], severity: str) -> int:
        """Count vulnerabilities by severity level."""
        if not isinstance(vuln_data, dict):
            return 0

        vulns = vuln_data.get('vulnerabilities', [])
        if not isinstance(vulns, list):
            return 0

        count = 0
        for vuln in vulns:
            if isinstance(vuln, dict) and vuln.get('severity', '').lower() == severity.lower():
                count += 1

        return count

    def _calculate_risk_score(self, vuln_data: Dict[str, Any]) -> float:
        """Calculate overall risk score."""
        if not isinstance(vuln_data, dict):
            return 0.0

        vulns = vuln_data.get('vulnerabilities', [])
        if not isinstance(vulns, list):
            return 0.0

        score = 0.0
        for vuln in vulns:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', '').lower()
                if severity == 'critical':
                    score += 10.0
                elif severity == 'high':
                    score += 7.0
                elif severity == 'medium':
                    score += 4.0
                elif severity == 'low':
                    score += 1.0

        return min(score, 100.0)

    def _dict_to_xml(self, data: Any, parent: ET.Element):
        """Convert dictionary to XML elements."""
        if isinstance(data, dict):
            for key, value in data.items():
                elem = ET.SubElement(parent, str(key).replace(' ', '_'))
                self._dict_to_xml(value, elem)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                elem = ET.SubElement(parent, f"item_{i}")
                self._dict_to_xml(item, elem)
        else:
            parent.text = str(data)

    def _extract_raw_data_samples(self) -> Dict[str, str]:
        """Extract sample raw data from binary."""
        samples = {}

        try:
            if os.path.exists(self.binary_path):
                with open(self.binary_path, 'rb') as f:
                    # Read first 256 bytes
                    header_data = f.read(256)
                    samples['header_hex'] = header_data.hex()

                    # Read some data from middle
                    file_size = os.path.getsize(self.binary_path)
                    if file_size > 512:
                        f.seek(file_size // 2)
                        middle_data = f.read(128)
                        samples['middle_hex'] = middle_data.hex()
        except Exception:
            pass

        return samples

    def _export_vulnerabilities_csv(self, output_path: str) -> bool:
        """Export vulnerabilities as CSV."""
        vuln_data = self.analysis_results.get('vulnerabilities', {})
        vulns = vuln_data.get('vulnerabilities', []) if isinstance(vuln_data, dict) else []

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['severity', 'type', 'location', 'description', 'impact', 'recommendation']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for vuln in vulns:
                if isinstance(vuln, dict):
                    writer.writerow({
                        'severity': vuln.get('severity', 'Unknown'),
                        'type': vuln.get('type', 'Unknown'),
                        'location': vuln.get('location', 'Unknown'),
                        'description': vuln.get('description', 'No description'),
                        'impact': vuln.get('impact', 'Unknown'),
                        'recommendation': vuln.get('recommendation', 'Review manually')
                    })

        return True

    def _format_vulnerability_details(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format vulnerability details for reporting."""
        if not isinstance(vuln_data, dict):
            return []

        vulns = vuln_data.get('vulnerabilities', [])
        if not isinstance(vulns, list):
            return []

        formatted = []
        for vuln in vulns:
            if isinstance(vuln, dict):
                formatted.append({
                    'id': len(formatted) + 1,
                    'severity': vuln.get('severity', 'Unknown'),
                    'type': vuln.get('type', 'Unknown'),
                    'location': vuln.get('location', 'Unknown'),
                    'description': vuln.get('description', 'No description available'),
                    'impact': vuln.get('impact', 'Potential security compromise'),
                    'recommendation': vuln.get('recommendation', 'Manual review required'),
                    'cve_references': vuln.get('cve_references', []),
                    'exploit_likelihood': vuln.get('exploit_likelihood', 'Unknown')
                })

        return formatted

    def _generate_mitigation_strategies(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Generate mitigation strategies based on vulnerabilities."""
        self.logger.debug(f"Generating mitigation strategies for {len(vuln_data)} vulnerability categories")
        strategies = [
            "Implement input validation and sanitization",
            "Use safe string handling functions",
            "Enable compiler security features (stack canaries, ASLR, DEP)",
            "Conduct regular security code reviews",
            "Implement proper error handling",
            "Use memory-safe programming languages where appropriate",
            "Regular security testing and vulnerability assessments"
        ]
        return strategies

    def _generate_compliance_notes(self, vuln_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Generate compliance-related notes."""
        self.logger.debug(f"Generating compliance notes for {len(vuln_data)} vulnerability types")
        return {
            'OWASP_Top_10': [
                "Review against OWASP Top 10 vulnerabilities",
                "Implement OWASP secure coding practices"
            ],
            'NIST': [
                "Follow NIST Cybersecurity Framework guidelines",
                "Implement NIST security controls"
            ],
            'ISO_27001': [
                "Ensure compliance with ISO 27001 security standards",
                "Document security policies and procedures"
            ]
        }

    def _export_strings_csv(self, strings_data: List[str], output_path: str) -> bool:
        """
        Export strings to CSV format.
        
        This method exports extracted strings from the binary analysis to a CSV file
        with detailed information about each string including offset, content, and metadata.
        
        Args:
            strings_data: List of strings extracted from binary
            output_path: Path to output CSV file
            
        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Offset', 'String', 'Length', 'Type', 'Encoding', 'Section', 'Entropy'])
                
                # Get strings from analysis results if not provided
                if not strings_data and 'strings' in self.analysis_results:
                    strings_data = self.analysis_results['strings']
                
                # Handle both string lists and dictionaries
                if isinstance(strings_data, dict):
                    strings_list = strings_data.get('strings', [])
                else:
                    strings_list = strings_data
                
                for i, string_item in enumerate(strings_list):
                    if isinstance(string_item, dict):
                        # Detailed string info available
                        offset = string_item.get('offset', hex(i * 8))
                        string_val = string_item.get('value', string_item.get('string', ''))
                        length = string_item.get('length', len(string_val))
                        str_type = string_item.get('type', 'ASCII')
                        encoding = string_item.get('encoding', 'UTF-8')
                        section = string_item.get('section', 'Unknown')
                        entropy = string_item.get('entropy', self._calculate_string_entropy(string_val))
                    else:
                        # Simple string
                        string_val = str(string_item)
                        offset = hex(i * 8)
                        length = len(string_val)
                        str_type = 'ASCII' if string_val.isascii() else 'Unicode'
                        encoding = 'UTF-8'
                        section = 'Unknown'
                        entropy = self._calculate_string_entropy(string_val)
                    
                    writer.writerow([offset, string_val, length, str_type, encoding, section, f"{entropy:.2f}"])
            
            self.logger.info(f"Exported {len(strings_list)} strings to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"String CSV export failed: {e}")
            return False

    def _export_imports_csv(self, imports_data: List[Dict], output_path: str) -> bool:
        """
        Export imports to CSV format.
        
        This method exports the import table analysis results to a CSV file,
        including module names, function names, addresses, and ordinals.
        
        Args:
            imports_data: List of import dictionaries
            output_path: Path to output CSV file
            
        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                # Define all possible fields
                fieldnames = ['Module', 'Function', 'Address', 'Ordinal', 'Type', 'Delayed', 'Forwarded']
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                # Get imports from analysis results if not provided
                if not imports_data and 'imports' in self.analysis_results:
                    imports_data = self.analysis_results['imports']
                
                # Handle nested import structures
                if isinstance(imports_data, dict):
                    all_imports = []
                    for module, funcs in imports_data.items():
                        if isinstance(funcs, list):
                            for func in funcs:
                                if isinstance(func, dict):
                                    func['Module'] = module
                                    all_imports.append(func)
                                else:
                                    all_imports.append({
                                        'Module': module,
                                        'Function': str(func),
                                        'Address': 'Unknown'
                                    })
                    imports_data = all_imports
                
                # Write import data
                for imp in imports_data:
                    if isinstance(imp, dict):
                        # Ensure required fields exist
                        if 'Module' not in imp and 'module' in imp:
                            imp['Module'] = imp['module']
                        if 'Function' not in imp and 'function' in imp:
                            imp['Function'] = imp['function']
                        if 'Function' not in imp and 'name' in imp:
                            imp['Function'] = imp['name']
                        if 'Address' not in imp and 'address' in imp:
                            imp['Address'] = imp['address']
                        
                        # Add additional fields
                        imp['Type'] = imp.get('type', 'Import')
                        imp['Delayed'] = imp.get('delayed', False)
                        imp['Forwarded'] = imp.get('forwarded', False)
                        
                        writer.writerow(imp)
            
            self.logger.info(f"Exported {len(imports_data)} imports to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Imports CSV export failed: {e}")
            return False

    def _export_comprehensive_csv(self, data: Dict[str, Any], output_path: str) -> bool:
        """
        Export comprehensive analysis to CSV.
        
        This method exports a comprehensive overview of all analysis results to CSV,
        with each analysis category and its key findings in a structured format.
        
        Args:
            data: Comprehensive analysis data dictionary
            output_path: Path to output CSV file
            
        Returns:
            bool: True if export successful, False otherwise
        """
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Analysis Type', 'Category', 'Result', 'Details', 'Severity', 'Count'])
                
                # Use analysis results if no data provided
                if not data:
                    data = self.analysis_results
                
                # Process each analysis category
                for analysis_type, results in data.items():
                    if isinstance(results, dict):
                        # Dictionary results
                        for key, value in results.items():
                            details = self._format_value_for_csv(value)
                            severity = self._assess_result_severity(analysis_type, key, value)
                            count = len(value) if isinstance(value, (list, dict)) else 1
                            writer.writerow([analysis_type, key, str(value)[:100], details, severity, count])
                    elif isinstance(results, list):
                        # List results
                        details = f"{len(results)} items"
                        severity = self._assess_result_severity(analysis_type, 'list', results)
                        writer.writerow([analysis_type, 'Results', f"List of {len(results)}", details, severity, len(results)])
                    else:
                        # Single value
                        writer.writerow([analysis_type, 'Value', str(results)[:100], type(results).__name__, 'Info', 1])
            
            self.logger.info(f"Exported comprehensive analysis to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Comprehensive CSV export failed: {e}")
            return False

    def _generate_analysis_config(self) -> Dict[str, Any]:
        """
        Generate analysis configuration.
        
        This method creates a configuration dictionary that can be used to
        reproduce the analysis with the same settings and parameters.
        
        Returns:
            Dictionary containing analysis configuration
        """
        config = {
            "version": self.export_metadata['export_version'],
            "timestamp": self.export_metadata['export_time'],
            "binary": {
                "path": self.binary_path,
                "name": os.path.basename(self.binary_path),
                "size": os.path.getsize(self.binary_path) if os.path.exists(self.binary_path) else 0,
                "hash": self._calculate_file_hash(self.binary_path)
            },
            "analysis_types": list(self.analysis_results.keys()),
            "scan_depth": "deep",
            "options": {
                "strings_extraction": True,
                "imports_analysis": True,
                "exports_analysis": True,
                "vulnerability_scan": True,
                "protection_detection": True,
                "metadata_extraction": True,
                "behavioral_analysis": False,
                "network_analysis": False
            },
            "thresholds": {
                "min_string_length": 4,
                "max_string_length": 1024,
                "entropy_threshold": 7.0,
                "confidence_threshold": 0.7
            },
            "output_formats": get_available_formats()
        }
        
        # Add analysis-specific configurations
        if 'vulnerabilities' in self.analysis_results:
            config['vulnerability_config'] = {
                "scan_level": "comprehensive",
                "check_types": ["buffer_overflow", "format_string", "integer_overflow", "use_after_free"],
                "severity_levels": ["critical", "high", "medium", "low"]
            }
        
        return config

    def _generate_detection_rules(self, analysis_data: Dict[str, Any] = None) -> List[Dict[str, str]]:
        """
        Generate detection rules based on analysis results.
        
        This method creates detection rules that can be used by security tools
        to identify similar binaries or patterns based on the analysis findings.
        
        Args:
            analysis_data: Optional specific analysis data to generate rules from
            
        Returns:
            List of detection rule dictionaries
        """
        if not analysis_data:
            analysis_data = self.analysis_results
        
        rules = []
        rule_id = 1
        
        # Generate rules based on strings
        if 'strings' in analysis_data:
            suspicious_strings = self._find_suspicious_strings(analysis_data['strings'])
            for string in suspicious_strings[:5]:  # Top 5 suspicious strings
                rules.append({
                    "rule_id": f"STR_{rule_id:03d}",
                    "type": "string_match",
                    "description": f"Suspicious string pattern: {string[:50]}...",
                    "pattern": string,
                    "severity": "medium",
                    "confidence": 0.7,
                    "tags": ["suspicious", "string_pattern"]
                })
                rule_id += 1
        
        # Generate rules based on imports
        if 'imports' in analysis_data:
            suspicious_imports = self._find_suspicious_imports(analysis_data['imports'])
            for imp in suspicious_imports[:5]:  # Top 5 suspicious imports
                rules.append({
                    "rule_id": f"IMP_{rule_id:03d}",
                    "type": "import_match",
                    "description": f"Suspicious import: {imp}",
                    "pattern": imp,
                    "severity": "high",
                    "confidence": 0.8,
                    "tags": ["suspicious", "import", "api_call"]
                })
                rule_id += 1
        
        # Generate rules based on vulnerabilities
        if 'vulnerabilities' in analysis_data:
            vuln_data = analysis_data['vulnerabilities']
            if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
                for vuln in vuln_data['vulnerabilities'][:3]:  # Top 3 vulnerabilities
                    if isinstance(vuln, dict):
                        rules.append({
                            "rule_id": f"VUL_{rule_id:03d}",
                            "type": "vulnerability_pattern",
                            "description": vuln.get('description', 'Vulnerability detected'),
                            "pattern": vuln.get('pattern', 'Unknown'),
                            "severity": vuln.get('severity', 'high'),
                            "confidence": 0.9,
                            "tags": ["vulnerability", vuln.get('type', 'unknown')]
                        })
                        rule_id += 1
        
        # Generate behavioral rules
        if 'behavior' in analysis_data:
            behaviors = analysis_data['behavior']
            if isinstance(behaviors, list):
                for behavior in behaviors[:3]:
                    rules.append({
                        "rule_id": f"BEH_{rule_id:03d}",
                        "type": "behavioral_pattern",
                        "description": f"Behavioral indicator: {behavior}",
                        "pattern": behavior,
                        "severity": "medium",
                        "confidence": 0.6,
                        "tags": ["behavior", "dynamic"]
                    })
                    rule_id += 1
        
        return rules

    def _create_summary_sheet(self, workbook, header_format, cell_format) -> None:
        """
        Create Excel summary sheet.
        
        Args:
            workbook: xlsxwriter workbook object
            header_format: Format for headers
            cell_format: Format for cells
        """
        worksheet = workbook.add_worksheet('Summary')
        
        # Headers
        worksheet.write(0, 0, 'Analysis Summary', header_format)
        worksheet.merge_range(0, 0, 0, 3, 'Analysis Summary', header_format)
        
        # Summary data
        summary = self._generate_summary()
        row = 2
        
        worksheet.write(row, 0, 'File Information', header_format)
        worksheet.write(row, 1, '', header_format)
        row += 1
        
        for key, value in summary['file_info'].items():
            worksheet.write(row, 0, key.replace('_', ' ').title(), cell_format)
            worksheet.write(row, 1, str(value), cell_format)
            row += 1
        
        row += 1
        worksheet.write(row, 0, 'Analysis Overview', header_format)
        worksheet.write(row, 1, 'Count', header_format)
        row += 1
        
        for analysis_type, count in summary['analysis_overview'].items():
            worksheet.write(row, 0, analysis_type.replace('_', ' ').title(), cell_format)
            worksheet.write(row, 1, count, cell_format)
            row += 1
        
        # Set column widths
        worksheet.set_column(0, 0, 30)
        worksheet.set_column(1, 1, 50)

    def _create_vulnerabilities_sheet(self, workbook, header_format, cell_format) -> None:
        """
        Create vulnerabilities sheet in Excel workbook.
        
        Args:
            workbook: xlsxwriter workbook object
            header_format: Format for headers
            cell_format: Format for cells
        """
        worksheet = workbook.add_worksheet('Vulnerabilities')
        
        # Headers
        headers = ['ID', 'Severity', 'Type', 'Location', 'Description', 'Impact', 'Recommendation']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # Vulnerability data
        vuln_data = self.analysis_results.get('vulnerabilities', {})
        formatted_vulns = self._format_vulnerability_details(vuln_data)
        
        row = 1
        for vuln in formatted_vulns:
            worksheet.write(row, 0, vuln.get('id', row), cell_format)
            worksheet.write(row, 1, vuln.get('severity', 'Unknown'), cell_format)
            worksheet.write(row, 2, vuln.get('type', 'Unknown'), cell_format)
            worksheet.write(row, 3, vuln.get('location', 'Unknown'), cell_format)
            worksheet.write(row, 4, vuln.get('description', ''), cell_format)
            worksheet.write(row, 5, vuln.get('impact', ''), cell_format)
            worksheet.write(row, 6, vuln.get('recommendation', ''), cell_format)
            row += 1
        
        # Set column widths
        worksheet.set_column(0, 0, 10)
        worksheet.set_column(1, 1, 15)
        worksheet.set_column(2, 2, 20)
        worksheet.set_column(3, 3, 30)
        worksheet.set_column(4, 6, 40)

    def _create_strings_sheet(self, workbook, header_format, cell_format) -> None:
        """
        Create strings analysis sheet in Excel workbook.
        
        Args:
            workbook: xlsxwriter workbook object
            header_format: Format for headers
            cell_format: Format for cells
        """
        worksheet = workbook.add_worksheet('Strings')
        
        # Headers
        headers = ['Offset', 'String', 'Length', 'Type', 'Encoding', 'Entropy']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # String data
        strings_data = self.analysis_results.get('strings', [])
        if isinstance(strings_data, dict):
            strings_list = strings_data.get('strings', [])
        else:
            strings_list = strings_data
        
        # Limit to first 1000 strings for Excel
        row = 1
        for i, string_item in enumerate(strings_list[:1000]):
            if isinstance(string_item, dict):
                offset = string_item.get('offset', hex(i * 8))
                string_val = string_item.get('value', string_item.get('string', ''))
                length = string_item.get('length', len(string_val))
                str_type = string_item.get('type', 'ASCII')
                encoding = string_item.get('encoding', 'UTF-8')
                entropy = string_item.get('entropy', 0)
            else:
                string_val = str(string_item)
                offset = hex(i * 8)
                length = len(string_val)
                str_type = 'ASCII' if string_val.isascii() else 'Unicode'
                encoding = 'UTF-8'
                entropy = self._calculate_string_entropy(string_val)
            
            worksheet.write(row, 0, offset, cell_format)
            worksheet.write(row, 1, string_val[:255], cell_format)  # Excel cell limit
            worksheet.write(row, 2, length, cell_format)
            worksheet.write(row, 3, str_type, cell_format)
            worksheet.write(row, 4, encoding, cell_format)
            worksheet.write(row, 5, f"{entropy:.2f}", cell_format)
            row += 1
        
        # Set column widths
        worksheet.set_column(0, 0, 15)
        worksheet.set_column(1, 1, 60)
        worksheet.set_column(2, 5, 15)

    def _create_imports_sheet(self, workbook, header_format, cell_format) -> None:
        """
        Create imports analysis sheet in Excel workbook.
        
        Args:
            workbook: xlsxwriter workbook object
            header_format: Format for headers
            cell_format: Format for cells
        """
        worksheet = workbook.add_worksheet('Imports')
        
        # Headers
        headers = ['Module', 'Function', 'Address', 'Ordinal', 'Type']
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # Import data
        imports_data = self.analysis_results.get('imports', {})
        
        row = 1
        if isinstance(imports_data, dict):
            for module, funcs in imports_data.items():
                if isinstance(funcs, list):
                    for func in funcs:
                        if isinstance(func, dict):
                            worksheet.write(row, 0, module, cell_format)
                            worksheet.write(row, 1, func.get('name', func.get('Function', '')), cell_format)
                            worksheet.write(row, 2, func.get('address', 'Unknown'), cell_format)
                            worksheet.write(row, 3, func.get('ordinal', ''), cell_format)
                            worksheet.write(row, 4, func.get('type', 'Import'), cell_format)
                        else:
                            worksheet.write(row, 0, module, cell_format)
                            worksheet.write(row, 1, str(func), cell_format)
                            worksheet.write(row, 2, 'Unknown', cell_format)
                            worksheet.write(row, 3, '', cell_format)
                            worksheet.write(row, 4, 'Import', cell_format)
                        row += 1
        
        # Set column widths
        worksheet.set_column(0, 0, 30)
        worksheet.set_column(1, 1, 40)
        worksheet.set_column(2, 2, 20)
        worksheet.set_column(3, 4, 15)

    def _create_statistics_sheet(self, workbook, header_format, cell_format) -> None:
        """
        Create statistics sheet in Excel workbook.
        
        Args:
            workbook: xlsxwriter workbook object
            header_format: Format for headers
            cell_format: Format for cells
        """
        worksheet = workbook.add_worksheet('Statistics')
        
        # Headers
        worksheet.write(0, 0, 'Analysis Statistics', header_format)
        worksheet.merge_range(0, 0, 0, 2, 'Analysis Statistics', header_format)
        
        # Generate statistics
        stats = self._generate_statistics()
        
        row = 2
        worksheet.write(row, 0, 'Category', header_format)
        worksheet.write(row, 1, 'Count', header_format)
        worksheet.write(row, 2, 'Details', header_format)
        row += 1
        
        # Basic statistics
        worksheet.write(row, 0, 'Total Analysis Categories', cell_format)
        worksheet.write(row, 1, stats['total_categories'], cell_format)
        worksheet.write(row, 2, 'Number of different analysis types performed', cell_format)
        row += 1
        
        worksheet.write(row, 0, 'Total Data Points', cell_format)
        worksheet.write(row, 1, stats['data_points'], cell_format)
        worksheet.write(row, 2, 'Total number of findings across all categories', cell_format)
        row += 1
        
        # Category breakdown
        row += 1
        worksheet.write(row, 0, 'Category Breakdown', header_format)
        worksheet.write(row, 1, '', header_format)
        worksheet.write(row, 2, '', header_format)
        row += 1
        
        for category, count in stats['categories'].items():
            worksheet.write(row, 0, category.replace('_', ' ').title(), cell_format)
            worksheet.write(row, 1, count, cell_format)
            worksheet.write(row, 2, f"Items in {category}", cell_format)
            row += 1
        
        # Set column widths
        worksheet.set_column(0, 0, 30)
        worksheet.set_column(1, 1, 15)
        worksheet.set_column(2, 2, 50)

    def _calculate_string_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count character frequencies
        char_counts = Counter(string)
        length = len(string)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        import hashlib
        
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "Unknown"

    def _find_suspicious_strings(self, strings_data) -> List[str]:
        """Find suspicious strings in string data."""
        suspicious_patterns = [
            'password', 'license', 'crack', 'patch', 'keygen',
            'bypass', 'debug', 'admin', 'root', 'backdoor',
            'http://', 'https://', 'ftp://', 'cmd.exe', 'powershell'
        ]
        
        suspicious = []
        
        if isinstance(strings_data, dict):
            strings_list = strings_data.get('strings', [])
        else:
            strings_list = strings_data
        
        for string_item in strings_list:
            if isinstance(string_item, dict):
                string_val = string_item.get('value', string_item.get('string', ''))
            else:
                string_val = str(string_item)
            
            string_lower = string_val.lower()
            for pattern in suspicious_patterns:
                if pattern in string_lower:
                    suspicious.append(string_val)
                    break
        
        return suspicious

    def _find_suspicious_imports(self, imports_data) -> List[str]:
        """Find suspicious imports."""
        suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
            'WriteProcessMemory', 'ReadProcessMemory', 'OpenProcess',
            'CreateToolhelp32Snapshot', 'SetWindowsHookEx', 'GetAsyncKeyState',
            'RegSetValueEx', 'CreateService', 'WinExec', 'ShellExecute'
        ]
        
        suspicious = []
        
        if isinstance(imports_data, dict):
            for module, funcs in imports_data.items():
                if isinstance(funcs, list):
                    for func in funcs:
                        func_name = func if isinstance(func, str) else func.get('name', func.get('Function', ''))
                        if any(api in func_name for api in suspicious_apis):
                            suspicious.append(f"{module}!{func_name}")
        
        return suspicious

    def _format_value_for_csv(self, value) -> str:
        """Format a value for CSV export."""
        if isinstance(value, list):
            return f"List of {len(value)} items"
        elif isinstance(value, dict):
            return f"Dictionary with {len(value)} keys"
        elif isinstance(value, bool):
            return "Yes" if value else "No"
        else:
            return str(value)[:100]

    def _assess_result_severity(self, analysis_type: str, key: str, value) -> str:
        """Assess severity of analysis result."""
        if analysis_type == 'vulnerabilities':
            if isinstance(value, list) and len(value) > 0:
                return 'High'
            return 'Low'
        elif analysis_type == 'protections':
            if key in ['aslr', 'dep', 'seh'] and not value:
                return 'Medium'
            return 'Info'
        elif analysis_type == 'imports':
            suspicious_apis = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']
            if any(api in str(value) for api in suspicious_apis):
                return 'Medium'
            return 'Info'
        else:
            return 'Info'


def get_available_formats() -> List[str]:
    """Get list of available export formats."""
    formats = ['json', 'markdown', 'html', 'txt', 'csv', 'xml']

    if YAML_AVAILABLE:
        formats.append('yaml')
    if XLSX_AVAILABLE:
        formats.append('xlsx')

    return formats


def export_analysis_results(binary_path: str, analysis_results: Dict[str, Any],
                          output_path: str, format_type: str, **kwargs) -> bool:
    """Export analysis results in specified format.

    Args:
        binary_path: Path to analyzed binary
        analysis_results: Analysis results dictionary
        output_path: Output file path
        format_type: Export format
        **kwargs: Additional format-specific options

    Returns:
        True if export successful
    """
    exporter = AdvancedExporter(binary_path, analysis_results)

    format_type = format_type.lower()

    if format_type == 'json':
        return exporter.export_detailed_json(output_path, kwargs.get('include_raw_data', True))
    elif format_type in ['markdown', 'html', 'txt']:
        return exporter.export_executive_summary(output_path, format_type)
    elif format_type == 'vulnerability':
        return exporter.export_vulnerability_report(output_path)
    elif format_type == 'csv':
        return exporter.export_csv_data(output_path, kwargs.get('data_type', 'all'))
    elif format_type == 'xml':
        return exporter.export_xml_report(output_path)
    elif format_type == 'yaml':
        return exporter.export_yaml_config(output_path)
    elif format_type == 'xlsx':
        return exporter.export_excel_workbook(output_path)
    else:
        print(f"Unsupported format: {format_type}")
        print(f"Available formats: {', '.join(get_available_formats())}")
        return False
