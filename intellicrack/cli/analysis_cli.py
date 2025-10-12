"""Command-line interface for running binary analysis.

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

import argparse
import datetime
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
from intellicrack.core.binary_analyzer import BinaryAnalyzer
from intellicrack.core.protection_analyzer import ProtectionAnalyzer
from intellicrack.utils.binary.elf_analyzer import ELFAnalyzer
from intellicrack.utils.binary.pe_analysis_common import PEAnalyzer
from intellicrack.utils.report_generator import ReportGenerator
from intellicrack.utils.system.os_detection import detect_file_type


class AnalysisCLI:
    """Command-line interface for binary analysis."""

    def __init__(self):
        """Initialize the CLI."""
        self.logger = self._setup_logging()
        self.binary_analyzer = BinaryAnalyzer()
        self.protection_analyzer = ProtectionAnalyzer()
        self.vulnerability_scanner = AdvancedVulnerabilityEngine()
        self.report_generator = ReportGenerator()

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger("AnalysisCLI")
        logger.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # File handler
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        file_handler = logging.FileHandler(log_dir / f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        file_handler.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    def analyze_binary(self, file_path: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive binary analysis."""
        self.logger.info(f"Starting analysis of: {file_path}")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "target_file": file_path,
            "file_hash": self._calculate_hash(file_path),
            "file_size": os.path.getsize(file_path),
            "analysis_type": "Comprehensive",
            "findings": [],
            "metadata": {},
            "vulnerabilities": [],
            "protections": [],
            "recommendations": [],
        }

        # Detect file type
        file_type = detect_file_type(file_path)
        results["metadata"]["file_type"] = file_type
        self.logger.info(f"Detected file type: {file_type}")

        # Binary analysis
        if options.get("binary_analysis", True):
            self.logger.info("Performing binary analysis...")
            try:
                binary_results = self.binary_analyzer.analyze(file_path)
                results["findings"].extend(self._format_findings(binary_results, "Binary Analysis"))
                results["metadata"]["binary_analysis"] = binary_results
            except Exception as e:
                self.logger.error(f"Binary analysis failed: {e}")
                results["findings"].append(
                    {
                        "type": "error",
                        "description": f"Binary analysis failed: {str(e)}",
                        "impact": "high",
                    }
                )

        # Protection analysis
        if options.get("protection_analysis", True):
            self.logger.info("Analyzing protection mechanisms...")
            try:
                protections = self.protection_analyzer.analyze_protections(file_path)
                results["protections"] = protections

                # Add findings based on protections
                for p in protections:
                    if p.get("status") == "enabled":
                        results["findings"].append(
                            {
                                "type": "protection",
                                "description": f"{p['type']} protection detected",
                                "impact": "medium",
                            }
                        )
            except Exception as e:
                self.logger.error(f"Protection analysis failed: {e}")

        # Vulnerability scanning
        if options.get("vulnerability_scan", True):
            self.logger.info("Scanning for vulnerabilities...")
            try:
                vulnerabilities = self.vulnerability_scanner.scan_binary(file_path)
                results["vulnerabilities"] = vulnerabilities

                # Generate recommendations based on vulnerabilities
                for v in vulnerabilities:
                    if v.get("severity") in ["critical", "high"]:
                        results["recommendations"].append(
                            f"Address {v['type']} vulnerability: {v.get('recommendation', 'Apply security patch')}"
                        )
            except Exception as e:
                self.logger.error(f"Vulnerability scanning failed: {e}")

        # PE-specific analysis
        if file_type == "PE" and options.get("pe_analysis", True):
            self.logger.info("Performing PE-specific analysis...")
            try:
                pe_analyzer = PEAnalyzer()
                pe_results = pe_analyzer.analyze(file_path)
                results["metadata"]["pe_analysis"] = pe_results

                # Check for suspicious imports
                if "imports" in pe_results:
                    suspicious_apis = self._check_suspicious_apis(pe_results["imports"])
                    if suspicious_apis:
                        results["findings"].append(
                            {
                                "type": "suspicious_api",
                                "description": f"Suspicious API calls detected: {', '.join(suspicious_apis)}",
                                "impact": "medium",
                            }
                        )
            except Exception as e:
                self.logger.error(f"PE analysis failed: {e}")

        # ELF-specific analysis
        if file_type == "ELF" and options.get("elf_analysis", True):
            self.logger.info("Performing ELF-specific analysis...")
            try:
                elf_analyzer = ELFAnalyzer()
                elf_results = elf_analyzer.analyze(file_path)
                results["metadata"]["elf_analysis"] = elf_results

                # Check for security features
                if "security_features" in elf_results:
                    for feature, enabled in elf_results["security_features"].items():
                        if not enabled:
                            results["recommendations"].append(f"Enable {feature} for improved security")
            except Exception as e:
                self.logger.error(f"ELF analysis failed: {e}")

        # String extraction
        if options.get("extract_strings", True):
            self.logger.info("Extracting strings...")
            try:
                strings = self._extract_strings(file_path)
                results["metadata"]["strings_count"] = len(strings)

                # Check for interesting strings
                interesting = self._find_interesting_strings(strings)
                if interesting:
                    results["findings"].append(
                        {
                            "type": "interesting_strings",
                            "description": f"Found {len(interesting)} interesting strings",
                            "impact": "low",
                            "details": interesting[:10],  # Limit to first 10
                        }
                    )
            except Exception as e:
                self.logger.error(f"String extraction failed: {e}")

        self.logger.info("Analysis complete")
        return results

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _format_findings(self, data: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
        """Format findings from analysis data."""
        findings = []

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (str, int, float, bool)):
                    findings.append(
                        {
                            "type": source.lower().replace(" ", "_"),
                            "description": f"{key}: {value}",
                            "impact": "low",
                        }
                    )

        return findings

    def _check_suspicious_apis(self, imports: Dict[str, List[str]]) -> List[str]:
        """Check for suspicious API calls."""
        suspicious_apis = [
            "VirtualProtect",
            "VirtualAlloc",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "OpenProcess",
            "SetWindowsHookEx",
            "GetAsyncKeyState",
            "GetKeyState",
            "RegSetValueEx",
            "CreateService",
            "StartService",
            "CryptEncrypt",
            "CryptDecrypt",
            "InternetOpen",
            "URLDownloadToFile",
            "WinExec",
            "ShellExecute",
        ]

        found = []
        for _dll, funcs in imports.items():
            for func in funcs:
                if func in suspicious_apis:
                    found.append(func)

        return found

    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary."""
        strings = []

        with open(file_path, "rb") as f:
            data = f.read()

        # ASCII strings
        current = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        # Unicode strings (simplified)
        current = []
        for i in range(0, len(data) - 1, 2):
            if data[i + 1] == 0 and 32 <= data[i] <= 126:
                current.append(chr(data[i]))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings

    def _find_interesting_strings(self, strings: List[str]) -> List[str]:
        """Find potentially interesting strings."""
        interesting_patterns = [
            "password",
            "passwd",
            "license",
            "serial",
            "crack",
            "patch",
            "keygen",
            "http://",
            "https://",
            ".exe",
            ".dll",
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "cmd.exe",
            "powershell",
            "reg.exe",
            "admin",
            "root",
            "sudo",
            "token",
            "api_key",
            "secret",
        ]

        interesting = []
        for s in strings:
            s_lower = s.lower()
            for pattern in interesting_patterns:
                if pattern in s_lower:
                    interesting.append(s)
                    break

        return interesting

    def generate_report(self, results: Dict[str, Any], format: str, output_file: str = None) -> str:
        """Generate analysis report."""
        self.logger.info(f"Generating {format} report...")

        report_path = self.report_generator.generate_report(results, format=format, output_file=output_file)

        self.logger.info(f"Report saved to: {report_path}")
        return report_path

    def run_batch_analysis(self, file_list: List[str], options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run analysis on multiple files."""
        results = []

        for file_path in file_list:
            try:
                self.logger.info(f"Analyzing {file_path} ({len(results) + 1}/{len(file_list)})")
                result = self.analyze_binary(file_path, options)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {e}")
                results.append(
                    {
                        "target_file": file_path,
                        "error": str(e),
                        "timestamp": datetime.datetime.now().isoformat(),
                    }
                )

        return results


def main():
    """Run main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Intellicrack Binary Analysis CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", help="Path to binary file or directory to analyze")

    parser.add_argument("-o", "--output", help="Output file for report", default=None)

    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html", "pdf", "xml", "csv", "markdown", "txt"],
        default="html",
        help="Report format (default: html)",
    )

    parser.add_argument("--no-binary-analysis", action="store_true", help="Skip binary analysis")

    parser.add_argument("--no-protection-analysis", action="store_true", help="Skip protection analysis")

    parser.add_argument("--no-vulnerability-scan", action="store_true", help="Skip vulnerability scanning")

    parser.add_argument("--no-pe-analysis", action="store_true", help="Skip PE-specific analysis")

    parser.add_argument("--no-elf-analysis", action="store_true", help="Skip ELF-specific analysis")

    parser.add_argument("--no-strings", action="store_true", help="Skip string extraction")

    parser.add_argument("-b", "--batch", action="store_true", help="Batch mode - analyze all files in directory")

    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively analyze files in subdirectories")

    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".exe", ".dll", ".so", ".elf", ".bin"],
        help="File extensions to analyze in batch mode",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output except errors")

    parser.add_argument("--json-output", action="store_true", help="Output results as JSON to stdout")

    args = parser.parse_args()

    # Set up logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize CLI
    cli = AnalysisCLI()

    # Prepare analysis options
    options = {
        "binary_analysis": not args.no_binary_analysis,
        "protection_analysis": not args.no_protection_analysis,
        "vulnerability_scan": not args.no_vulnerability_scan,
        "pe_analysis": not args.no_pe_analysis,
        "elf_analysis": not args.no_elf_analysis,
        "extract_strings": not args.no_strings,
    }

    try:
        if args.batch or os.path.isdir(args.target):
            # Batch mode
            target_dir = Path(args.target)

            if not target_dir.exists():
                print(f"Error: Directory not found: {args.target}", file=sys.stderr)
                sys.exit(1)

            # Collect files
            file_list = []
            if args.recursive:
                for ext in args.extensions:
                    file_list.extend(target_dir.rglob(f"*{ext}"))
            else:
                for ext in args.extensions:
                    file_list.extend(target_dir.glob(f"*{ext}"))

            file_list = [str(f) for f in file_list]

            if not file_list:
                print(f"No files found with extensions: {args.extensions}", file=sys.stderr)
                sys.exit(1)

            print(f"Found {len(file_list)} files to analyze")

            # Run batch analysis
            results = cli.run_batch_analysis(file_list, options)

            if args.json_output:
                print(json.dumps(results, indent=2))
            else:
                # Generate batch report
                for i, result in enumerate(results):
                    if "error" not in result:
                        output_file = f"report_{i + 1}_{Path(result['target_file']).stem}.{args.format}"
                        cli.generate_report(result, args.format, output_file)

                print(f"Analysis complete. {len(results)} files processed.")

        else:
            # Single file mode
            if not os.path.exists(args.target):
                print(f"Error: File not found: {args.target}", file=sys.stderr)
                sys.exit(1)

            # Run analysis
            results = cli.analyze_binary(args.target, options)

            if args.json_output:
                print(json.dumps(results, indent=2))
            else:
                # Generate report
                report_path = cli.generate_report(results, args.format, args.output)
                print(f"Analysis complete. Report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
