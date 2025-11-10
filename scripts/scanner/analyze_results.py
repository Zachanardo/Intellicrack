#!/usr/bin/env python3
"""Analyze scanner results and generate report."""

import json
import os
from collections import defaultdict
from pathlib import Path


def analyze_scan_results(json_file):
    """Parse and analyze scan results."""
    with open(json_file, 'r') as f:
        data = json.load(f)

    findings = data.get('findings', [])
    total_findings = data.get('total_findings', len(findings))
    severity_counts = data.get('severity_counts', {})

    # Group findings by type and file
    findings_by_type = defaultdict(list)
    findings_by_file = defaultdict(list)
    findings_by_severity = defaultdict(list)

    for finding in findings:
        findings_by_type[finding['finding_type']].append(finding)
        findings_by_file[finding['file']].append(finding)
        findings_by_severity[finding['severity']].append(finding)

    # Statistics
    print("=== SCANNER RESULTS SUMMARY ===")
    print(f"Total Findings: {total_findings}")
    print("\nSeverity Breakdown:")
    print(f"  Critical: {severity_counts.get('critical', 0)}")
    print(f"  High: {severity_counts.get('high', 0)}")
    print(f"  Medium: {severity_counts.get('medium', 0)}")

    print("\nFindings by Type:")
    for ftype, items in sorted(findings_by_type.items(), key=lambda x: -len(x[1])):
        print(f"  {ftype}: {len(items)}")

    print("\nMost Affected Files (Top 10):")
    sorted_files = sorted(findings_by_file.items(), key=lambda x: -len(x[1]))[:10]
    for filepath, items in sorted_files:
        # Simplify path for display
        short_path = str(Path(filepath).relative_to("D:/Intellicrack")) if filepath.startswith("D:/Intellicrack") else filepath
        print(f"  {short_path}: {len(items)} issues")

    # Sample findings for manual review
    print("\n=== SAMPLE FINDINGS FOR MANUAL REVIEW ===")

    # Get 5 critical, 5 high, 5 medium findings for review
    samples = []

    for severity in ['critical', 'high', 'medium']:
        severity_findings = findings_by_severity.get(severity, [])[:5]
        for finding in severity_findings:
            samples.append(finding)

    return {
        'total': total_findings,
        'severity_counts': severity_counts,
        'findings_by_type': {k: len(v) for k, v in findings_by_type.items()},
        'samples': samples,
        'all_findings': findings
    }

if __name__ == "__main__":
    json_file = "clean_scan_results.json"
    if not os.path.exists(json_file):
        print(f"Error: {json_file} not found!")
        exit(1)

    results = analyze_scan_results(json_file)

    # Save detailed analysis
    with open("analysis_summary.json", "w") as f:
        json.dump({
            'total': results['total'],
            'severity_counts': results['severity_counts'],
            'findings_by_type': results['findings_by_type']
        }, f, indent=2)

    print("\nAnalysis complete. Summary saved to analysis_summary.json")
