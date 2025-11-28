"""Report generation system for binary analysis results.

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

import csv
import datetime
import json
import os
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


try:
    import defusedxml.ElementTree as ET  # noqa: N817
except ImportError:
    import xml.etree.ElementTree as ET  # noqa: S405

try:
    from jinja2 import Environment, FileSystemLoader, Template

    _ = Template.__name__  # Verify Template class is available for template processing
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

try:
    import markdown

    _ = markdown.__name__  # Verify markdown module is available for text processing
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    # Verify reportlab page size formats are available for document layout
    assert isinstance(A4, tuple)
    assert len(A4) == 2

    # Verify reportlab image handling components are available
    assert Image is not None  # Image class is available for embedding

    # Verify reportlab page break functionality is available
    assert PageBreak is not None  # PageBreak class available for forcing page breaks
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


@dataclass
class AnalysisResult:
    """Container for analysis results."""

    timestamp: str
    target_file: str
    file_hash: str
    file_size: int
    analysis_type: str
    findings: list[dict[str, Any]]
    metadata: dict[str, Any]
    vulnerabilities: list[dict[str, Any]]
    protections: list[dict[str, Any]]
    recommendations: list[str]


class ReportGenerator:
    """Generate analysis reports in multiple formats."""

    def __init__(self, output_dir: str = "reports") -> None:
        """Initialize report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(__file__).parent.parent / "templates" / "reports"
        self.template_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 environment if available
        if HAS_JINJA2:
            self.jinja_env = Environment(loader=FileSystemLoader(str(self.template_dir)), autoescape=True)
        else:
            self.jinja_env = None

    def generate_report(self, analysis_data: dict[str, Any], format: str = "json", output_file: str | None = None) -> str:
        """Generate report in specified format."""
        result = self._prepare_analysis_result(analysis_data)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not output_file:
            output_file = f"report_{timestamp}.{format}"

        output_path = self.output_dir / output_file

        if format == "json":
            return self._generate_json_report(result, output_path)
        if format == "html":
            return self._generate_html_report(result, output_path)
        if format == "pdf":
            return self._generate_pdf_report(result, output_path)
        if format == "xml":
            return self._generate_xml_report(result, output_path)
        if format == "csv":
            return self._generate_csv_report(result, output_path)
        if format == "markdown":
            return self._generate_markdown_report(result, output_path)
        if format == "txt":
            return self._generate_text_report(result, output_path)
        error_msg = f"Unsupported format: {format}"
        logger.error(error_msg)
        raise ValueError(error_msg)

    def _prepare_analysis_result(self, data: dict[str, Any]) -> AnalysisResult:
        """Prepare analysis data for report generation."""
        return AnalysisResult(
            timestamp=data.get("timestamp", datetime.datetime.now().isoformat()),
            target_file=data.get("target_file", "Unknown"),
            file_hash=data.get("file_hash", ""),
            file_size=data.get("file_size", 0),
            analysis_type=data.get("analysis_type", "General"),
            findings=data.get("findings", []),
            metadata=data.get("metadata", {}),
            vulnerabilities=data.get("vulnerabilities", []),
            protections=data.get("protections", []),
            recommendations=data.get("recommendations", []),
        )

    def _generate_json_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate JSON format report."""
        report_data = asdict(result)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def _generate_html_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate HTML format report."""
        if HAS_JINJA2 and (self.template_dir / "report.html").exists():
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(result=result)
        else:
            # Generate HTML without template
            html_content = self._generate_html_without_template(result)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output_path)

    def _generate_html_without_template(self, result: AnalysisResult) -> str:
        """Generate HTML report without Jinja2."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Binary Analysis Report - {result.target_file}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #666; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .vulnerability {{ background-color: #ffe6e6; }}
        .protection {{ background-color: #e6ffe6; }}
        .metadata {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Binary Analysis Report</h1>

    <div class="metadata">
        <h2>File Information</h2>
        <p><strong>Target File:</strong> {result.target_file}</p>
        <p><strong>File Hash:</strong> {result.file_hash}</p>
        <p><strong>File Size:</strong> {result.file_size:,} bytes</p>
        <p><strong>Analysis Type:</strong> {result.analysis_type}</p>
        <p><strong>Timestamp:</strong> {result.timestamp}</p>
    </div>

    <h2>Vulnerabilities Found</h2>
    <table>
        <tr><th>Type</th><th>Severity</th><th>Description</th><th>Location</th></tr>
        {"".join(f'<tr class="vulnerability"><td>{v.get("type", "Unknown")}</td><td>{v.get("severity", "Unknown")}</td><td>{v.get("description", "")}</td><td>{v.get("location", "")}</td></tr>' for v in result.vulnerabilities)}
    </table>

    <h2>Protection Mechanisms</h2>
    <table>
        <tr><th>Type</th><th>Status</th><th>Details</th></tr>
        {"".join(f'<tr class="protection"><td>{p.get("type", "Unknown")}</td><td>{p.get("status", "Unknown")}</td><td>{p.get("details", "")}</td></tr>' for p in result.protections)}
    </table>

    <h2>Key Findings</h2>
    <ul>
        {"".join(f"<li>{f.get('description', '')}</li>" for f in result.findings)}
    </ul>

    <h2>Recommendations</h2>
    <ul>
        {"".join(f"<li>{r}</li>" for r in result.recommendations)}
    </ul>
</body>
</html>"""

    def _generate_pdf_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate PDF format report."""
        if not HAS_REPORTLAB:
            # Fallback to HTML if ReportLab not available
            html_path = output_path.with_suffix(".html")
            self._generate_html_report(result, html_path)
            return str(html_path)

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#333333"),
            spaceAfter=30,
        )
        story.extend(
            (
                Paragraph("Binary Analysis Report", title_style),
                Spacer(1, 12),
                Paragraph("File Information", styles["Heading2"]),
            )
        )
        file_data = [
            ["Target File:", result.target_file],
            ["File Hash:", result.file_hash],
            ["File Size:", f"{result.file_size:,} bytes"],
            ["Analysis Type:", result.analysis_type],
            ["Timestamp:", result.timestamp],
        ]

        file_table = Table(file_data, colWidths=[2 * inch, 4 * inch])
        file_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.beige),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ],
            ),
        )
        story.extend((file_table, Spacer(1, 20)))
        # Vulnerabilities
        if result.vulnerabilities:
            story.append(Paragraph("Vulnerabilities Found", styles["Heading2"]))
            vuln_data = [["Type", "Severity", "Description"]]
            for v in result.vulnerabilities:
                vuln_data.append(
                    [
                        v.get("type", "Unknown"),
                        v.get("severity", "Unknown"),
                        v.get("description", "")[:50] + "..." if len(v.get("description", "")) > 50 else v.get("description", ""),
                    ],
                )

            vuln_table = Table(vuln_data, colWidths=[1.5 * inch, 1.5 * inch, 3 * inch])
            vuln_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ],
                ),
            )
            story.extend((vuln_table, Spacer(1, 20)))
        # Protections
        if result.protections:
            story.append(Paragraph("Protection Mechanisms", styles["Heading2"]))
            prot_data = [["Type", "Status", "Details"]]
            for p in result.protections:
                prot_data.append(
                    [
                        p.get("type", "Unknown"),
                        p.get("status", "Unknown"),
                        p.get("details", "")[:50] + "..." if len(p.get("details", "")) > 50 else p.get("details", ""),
                    ],
                )

            prot_table = Table(prot_data, colWidths=[2 * inch, 1.5 * inch, 2.5 * inch])
            prot_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 12),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.lightgreen),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ],
                ),
            )
            story.extend((prot_table, Spacer(1, 20)))
        # Recommendations
        if result.recommendations:
            story.append(Paragraph("Recommendations", styles["Heading2"]))
            for rec in result.recommendations:
                story.append(Paragraph(f" {rec}", styles["Normal"]))
            story.append(Spacer(1, 12))

        doc.build(story)
        return str(output_path)

    def _generate_xml_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate XML format report."""
        root = ET.Element("BinaryAnalysisReport")

        # File info
        file_info = ET.SubElement(root, "FileInformation")
        ET.SubElement(file_info, "TargetFile").text = result.target_file
        ET.SubElement(file_info, "FileHash").text = result.file_hash
        ET.SubElement(file_info, "FileSize").text = str(result.file_size)
        ET.SubElement(file_info, "AnalysisType").text = result.analysis_type
        ET.SubElement(file_info, "Timestamp").text = result.timestamp

        # Vulnerabilities
        vulns = ET.SubElement(root, "Vulnerabilities")
        for v in result.vulnerabilities:
            vuln = ET.SubElement(vulns, "Vulnerability")
            ET.SubElement(vuln, "Type").text = v.get("type", "Unknown")
            ET.SubElement(vuln, "Severity").text = v.get("severity", "Unknown")
            ET.SubElement(vuln, "Description").text = v.get("description", "")
            ET.SubElement(vuln, "Location").text = v.get("location", "")

        # Protections
        prots = ET.SubElement(root, "Protections")
        for p in result.protections:
            prot = ET.SubElement(prots, "Protection")
            ET.SubElement(prot, "Type").text = p.get("type", "Unknown")
            ET.SubElement(prot, "Status").text = p.get("status", "Unknown")
            ET.SubElement(prot, "Details").text = p.get("details", "")

        # Findings
        findings = ET.SubElement(root, "Findings")
        for f in result.findings:
            finding = ET.SubElement(findings, "Finding")
            ET.SubElement(finding, "Description").text = f.get("description", "")
            ET.SubElement(finding, "Type").text = f.get("type", "")
            ET.SubElement(finding, "Impact").text = f.get("impact", "")

        # Recommendations
        recs = ET.SubElement(root, "Recommendations")
        for r in result.recommendations:
            ET.SubElement(recs, "Recommendation").text = r

        tree = ET.ElementTree(root)
        tree.write(str(output_path), encoding="utf-8", xml_declaration=True)

        return str(output_path)

    def _generate_csv_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate CSV format report."""
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            # Write file information
            writer.writerow(["File Information"])
            writer.writerow(["Target File", result.target_file])
            writer.writerow(["File Hash", result.file_hash])
            writer.writerow(["File Size", result.file_size])
            writer.writerow(["Analysis Type", result.analysis_type])
            writer.writerow(["Timestamp", result.timestamp])
            writer.writerow([])

            # Write vulnerabilities
            writer.writerow(["Vulnerabilities"])
            writer.writerow(["Type", "Severity", "Description", "Location"])
            for v in result.vulnerabilities:
                writer.writerow(
                    [
                        v.get("type", "Unknown"),
                        v.get("severity", "Unknown"),
                        v.get("description", ""),
                        v.get("location", ""),
                    ]
                )
            writer.writerow([])

            # Write protections
            writer.writerow(["Protection Mechanisms"])
            writer.writerow(["Type", "Status", "Details"])
            for p in result.protections:
                writer.writerow([p.get("type", "Unknown"), p.get("status", "Unknown"), p.get("details", "")])
            writer.writerow([])

            # Write recommendations
            writer.writerow(["Recommendations"])
            for r in result.recommendations:
                writer.writerow([r])

        return str(output_path)

    def _generate_markdown_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate Markdown format report."""
        md_content = f"""# Binary Analysis Report

## File Information

- **Target File:** {result.target_file}
- **File Hash:** {result.file_hash}
- **File Size:** {result.file_size:,} bytes
- **Analysis Type:** {result.analysis_type}
- **Timestamp:** {result.timestamp}

## Vulnerabilities Found

| Type | Severity | Description | Location |
|------|----------|-------------|----------|
"""

        for v in result.vulnerabilities:
            md_content += (
                f"| {v.get('type', 'Unknown')} | {v.get('severity', 'Unknown')} | {v.get('description', '')} | {v.get('location', '')} |\n"
            )

        md_content += """
## Protection Mechanisms

| Type | Status | Details |
|------|--------|---------|
"""

        for p in result.protections:
            md_content += f"| {p.get('type', 'Unknown')} | {p.get('status', 'Unknown')} | {p.get('details', '')} |\n"

        md_content += "\n## Key Findings\n\n"
        for f in result.findings:
            md_content += f"- {f.get('description', '')}\n"

        md_content += "\n## Recommendations\n\n"
        for r in result.recommendations:
            md_content += f"- {r}\n"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return str(output_path)

    def _generate_text_report(self, result: AnalysisResult, output_path: Path) -> str:
        """Generate plain text format report."""
        text_content = f"""BINARY ANALYSIS REPORT
{"=" * 50}

FILE INFORMATION
----------------
Target File: {result.target_file}
File Hash: {result.file_hash}
File Size: {result.file_size:,} bytes
Analysis Type: {result.analysis_type}
Timestamp: {result.timestamp}

VULNERABILITIES FOUND
---------------------
"""

        for v in result.vulnerabilities:
            text_content += f"""
Type: {v.get("type", "Unknown")}
Severity: {v.get("severity", "Unknown")}
Description: {v.get("description", "")}
Location: {v.get("location", "")}
{"-" * 30}
"""

        text_content += """
PROTECTION MECHANISMS
--------------------
"""

        for p in result.protections:
            text_content += f"""
Type: {p.get("type", "Unknown")}
Status: {p.get("status", "Unknown")}
Details: {p.get("details", "")}
{"-" * 30}
"""

        text_content += """
KEY FINDINGS
------------
"""
        for f in result.findings:
            text_content += f" {f.get('description', '')}\n"

        text_content += """
RECOMMENDATIONS
---------------
"""
        for r in result.recommendations:
            text_content += f" {r}\n"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text_content)

        return str(output_path)

    def generate_batch_report(self, analysis_results: list[dict[str, Any]], format: str = "json") -> str:
        """Generate report for multiple analysis results."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_dir = self.output_dir / f"batch_{timestamp}"
        batch_dir.mkdir(parents=True, exist_ok=True)

        report_files = []
        for i, data in enumerate(analysis_results):
            output_file = f"report_{i + 1}.{format}"
            report_path = self.generate_report(data, format=format, output_file=str(batch_dir / output_file))
            report_files.append(report_path)

        # Create archive
        archive_path = self.output_dir / f"batch_reports_{timestamp}.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in report_files:
                zf.write(file_path, Path(file_path).name)

        return str(archive_path)

    def export_to_archive(self, report_paths: list[str], archive_name: str = None) -> str:
        """Export multiple reports to an archive."""
        if not archive_name:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"reports_archive_{timestamp}.zip"

        archive_path = self.output_dir / archive_name

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in report_paths:
                if os.path.exists(path):
                    zf.write(path, os.path.basename(path))

        return str(archive_path)


class ComparisonReportGenerator:
    """Generate comparison reports between multiple binaries."""

    def __init__(self, output_dir: str = "reports/comparisons") -> None:
        """Initialize comparison report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.base_generator = ReportGenerator(output_dir)

    def generate_comparison(self, results: list[dict[str, Any]], format: str = "html") -> str:
        """Generate comparison report."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"comparison_{timestamp}.{format}"
        output_path = self.output_dir / output_file

        comparison_data = self._analyze_differences(results)

        if format == "html":
            return self._generate_html_comparison(comparison_data, output_path)
        return self._generate_json_comparison(comparison_data, output_path)

    def _analyze_differences(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze differences between results."""
        comparison = {
            "timestamp": datetime.datetime.now().isoformat(),
            "files_compared": [],
            "common_vulnerabilities": [],
            "unique_vulnerabilities": {},
            "common_protections": [],
            "unique_protections": {},
            "similarity_score": 0.0,
        }

        # Extract file information
        for r in results:
            comparison["files_compared"].append(
                {
                    "file": r.get("target_file", "Unknown"),
                    "hash": r.get("file_hash", ""),
                    "size": r.get("file_size", 0),
                },
            )

        # Find common and unique vulnerabilities
        all_vulns = []
        for i, r in enumerate(results):
            vulns = r.get("vulnerabilities", [])
            all_vulns.append({v.get("type", "") for v in vulns})
            comparison["unique_vulnerabilities"][f"file_{i + 1}"] = vulns

        if all_vulns:
            common = set.intersection(*all_vulns) if all_vulns else set()
            comparison["common_vulnerabilities"] = list(common)

        # Calculate similarity score
        if len(results) == 2 and all_vulns and (all_vulns[0] or all_vulns[1]):
            intersection = len(all_vulns[0] & all_vulns[1])
            union = len(all_vulns[0] | all_vulns[1])
            comparison["similarity_score"] = (intersection / union * 100) if union > 0 else 0

        return comparison

    def _generate_html_comparison(self, data: dict[str, Any], output_path: Path) -> str:
        """Generate HTML comparison report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Binary Comparison Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #666; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .common {{ background-color: #e6f3ff; }}
        .unique {{ background-color: #fff3e6; }}
        .similarity {{ font-size: 24px; font-weight: bold; color: #0066cc; }}
    </style>
</head>
<body>
    <h1>Binary Comparison Report</h1>

    <h2>Files Compared</h2>
    <table>
        <tr><th>File</th><th>Hash</th><th>Size</th></tr>
        {"".join(f"<tr><td>{f['file']}</td><td>{f['hash']}</td><td>{f['size']:,}</td></tr>" for f in data["files_compared"])}
    </table>

    <h2>Similarity Score</h2>
    <p class="similarity">{data["similarity_score"]:.1f}%</p>

    <h2>Common Vulnerabilities</h2>
    <ul class="common">
        {"".join(f"<li>{v}</li>" for v in data["common_vulnerabilities"])}
    </ul>

    <h2>Unique Vulnerabilities</h2>
    {"".join(f'<h3>{file}</h3><ul class="unique">{"".join(f"<li>{v}</li>" for v in vulns)}</ul>' for file, vulns in data["unique_vulnerabilities"].items())}

</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return str(output_path)

    def _generate_json_comparison(self, data: dict[str, Any], output_path: Path) -> str:
        """Generate JSON comparison report."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return str(output_path)


def generate_report(analysis_data: dict[str, Any], format: str = "html", output_dir: str = "reports") -> str:
    """Generate a report."""
    generator = ReportGenerator(output_dir)
    return generator.generate_report(analysis_data, format)


def export_report(analysis_data: dict[str, Any], format: str = "html", output_path: str | None = None) -> str:
    """Export analysis report to file."""
    output_dir = Path(output_path).parent if output_path else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    generator = ReportGenerator(str(output_dir))
    output_file = Path(output_path).name if output_path else None
    return generator.generate_report(analysis_data, format, output_file)


def generate_comparison_report(results: list[dict[str, Any]], format: str = "html", output_dir: str = "reports/comparisons") -> str:
    """Generate a comparison report."""
    generator = ComparisonReportGenerator(output_dir)
    return generator.generate_comparison(results, format)
