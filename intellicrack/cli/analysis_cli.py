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
from typing import Any


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
from intellicrack.core.binary_analyzer import BinaryAnalyzer
from intellicrack.core.protection_analyzer import ProtectionAnalyzer
from intellicrack.utils.binary.elf_analyzer import ELFAnalyzer
from intellicrack.utils.binary.pe_analysis_common import PEAnalyzer
from intellicrack.utils.report_generator import ReportGenerator
from intellicrack.utils.system.os_detection import detect_file_type


logger = logging.getLogger(__name__)


class AnalysisCLI:
    """Command-line interface for binary analysis."""

    def __init__(self) -> None:
        """Initialize the CLI."""
        self.logger = self._setup_logging()
        self.binary_analyzer = BinaryAnalyzer()
        self.protection_analyzer = ProtectionAnalyzer()
        self.vulnerability_scanner = AdvancedVulnerabilityEngine()
        self.report_generator = ReportGenerator()

    @staticmethod
    def _setup_logging() -> logging.Logger:
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

    def analyze_binary(self, file_path: str, options: dict[str, Any]) -> dict[str, Any]:
        """Perform comprehensive binary analysis."""
        self.logger.info("Starting analysis of: %s", file_path)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        results: dict[str, Any] = {
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
        self.logger.info("Detected file type: %s", file_type)

        # Perform individual analysis steps
        self._perform_binary_analysis(file_path, options, results)
        self._perform_protection_analysis(file_path, options, results)
        self._perform_vulnerability_scan(file_path, options, results)
        self._perform_pe_analysis(file_path, file_type, options, results)
        self._perform_elf_analysis(file_path, file_type, options, results)
        self._perform_string_extraction(file_path, options, results)

        self.logger.info("Analysis complete")
        return results

    def _perform_binary_analysis(self, file_path: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform binary analysis."""
        if options.get("binary_analysis", True):
            self.logger.info("Performing binary analysis...")
            try:
                binary_results = self.binary_analyzer.analyze(file_path)
                results["findings"].extend(self._format_findings(binary_results, "Binary Analysis"))
                results["metadata"]["binary_analysis"] = binary_results
            except Exception as e:
                self.logger.exception("Binary analysis failed: %s", e)
                results["findings"].append(
                    {
                        "type": "error",
                        "description": f"Binary analysis failed: {e!s}",
                        "impact": "high",
                    },
                )

    def _perform_protection_analysis(self, file_path: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform protection analysis."""
        if options.get("protection_analysis", True):
            self.logger.info("Analyzing protection mechanisms...")
            try:
                protections = self.protection_analyzer.analyze(file_path)
                results["protections"] = protections
                if isinstance(protections, dict):
                    for key, value in protections.items():
                        if isinstance(value, dict) and value.get("status") == "enabled":
                            results["findings"].append(
                                {
                                    "type": "protection",
                                    "description": f"{key} protection detected",
                                    "impact": "medium",
                                },
                            )
            except Exception as e:
                self.logger.exception("Protection analysis failed: %s", e)

    def _perform_vulnerability_scan(self, file_path: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform vulnerability scanning."""
        if options.get("vulnerability_scan", True):
            self.logger.info("Scanning for vulnerabilities...")
            try:
                vulnerabilities = self.vulnerability_scanner.scan_binary(file_path)
                results["vulnerabilities"] = vulnerabilities
                for v in vulnerabilities:
                    if v.get("severity") in {"critical", "high"}:
                        results["recommendations"].append(
                            f"Address {v['type']} vulnerability: {v.get('recommendation', 'Apply security patch')}",
                        )
            except Exception as e:
                self.logger.exception("Vulnerability scanning failed: %s", e)

    def _perform_pe_analysis(self, file_path: str, file_type: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform PE-specific analysis."""
        if file_type == "PE" and options.get("pe_analysis", True):
            self.logger.info("Performing PE-specific analysis...")
            try:
                pe_analyzer = PEAnalyzer()
                pe_results = pe_analyzer.analyze(file_path)
                results["metadata"]["pe_analysis"] = pe_results
                if "imports" in pe_results:
                    if suspicious_apis := self._check_suspicious_apis(
                        pe_results["imports"]
                    ):
                        results["findings"].append(
                            {
                                "type": "suspicious_api",
                                "description": f"Suspicious API calls detected: {', '.join(suspicious_apis)}",
                                "impact": "medium",
                            },
                        )
            except Exception as e:
                self.logger.exception("PE analysis failed: %s", e)

    def _perform_elf_analysis(self, file_path: str, file_type: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform ELF-specific analysis."""
        if file_type == "ELF" and options.get("elf_analysis", True):
            self.logger.info("Performing ELF-specific analysis...")
            try:
                elf_analyzer = ELFAnalyzer(file_path)
                elf_results = elf_analyzer.analyze()
                results["metadata"]["elf_analysis"] = elf_results
                if "security_features" in elf_results:
                    for feature, enabled in elf_results["security_features"].items():
                        if not enabled:
                            results["recommendations"].append(f"Enable {feature} for improved security")
            except Exception as e:
                self.logger.exception("ELF analysis failed: %s", e)

    def _perform_string_extraction(self, file_path: str, options: dict[str, Any], results: dict[str, Any]) -> None:
        """Helper to perform string extraction."""
        if options.get("extract_strings", True):
            self.logger.info("Extracting strings...")
            try:
                strings = self._extract_strings(file_path)
                results["metadata"]["strings_count"] = len(strings)
                if interesting := self._find_interesting_strings(strings):
                    results["findings"].append(
                        {
                            "type": "interesting_strings",
                            "description": f"Found {len(interesting)} interesting strings",
                            "impact": "low",
                            "details": interesting[:10],
                        },
                    )
            except Exception as e:
                self.logger.exception("String extraction failed: %s", e)

    @staticmethod
    def _calculate_hash(file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def _format_findings(data: dict[str, Any], source: str) -> list[dict[str, Any]]:
        """Format findings from analysis data."""
        findings: list[dict[str, Any]] = []

        if isinstance(data, dict):
            findings.extend(
                {
                    "type": source.lower().replace(" ", "_"),
                    "description": f"{key}: {value}",
                    "impact": "low",
                }
                for key, value in data.items()
                if isinstance(value, (str, int, float, bool))
            )
        return findings

    @staticmethod
    def _check_suspicious_apis(imports: dict[str, list[str]]) -> list[str]:
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
        for funcs in imports.values():
            found.extend(func for func in funcs if func in suspicious_apis)
        return found

    @staticmethod
    def _extract_strings(file_path: str, min_length: int = 4) -> list[str]:
        """Extract printable strings from binary."""
        MIN_PRINTABLE_ASCII = 32
        MAX_PRINTABLE_ASCII = 126

        strings = []

        with open(file_path, "rb") as f:
            data = f.read()

        # ASCII strings
        current = []
        for byte in data:
            if MIN_PRINTABLE_ASCII <= byte <= MAX_PRINTABLE_ASCII:  # Printable ASCII
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
            if data[i + 1] == 0 and MIN_PRINTABLE_ASCII <= data[i] <= MAX_PRINTABLE_ASCII:
                current.append(chr(data[i]))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

        return strings

    @staticmethod
    def _find_interesting_strings(strings: list[str]) -> list[str]:
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

    def generate_report(self, results: dict[str, Any], format: str, output_file: str | None = None) -> str:
        """Generate analysis report."""
        self.logger.info("Generating %s report...", format)

        report_path = self.report_generator.generate_report(results, format=format, output_file=output_file)

        self.logger.info("Report saved to: %s", report_path)
        return report_path

    def run_batch_analysis(self, file_list: list[str], options: dict[str, Any]) -> list[dict[str, Any]]:
        """Run analysis on multiple files."""
        results: list[dict[str, Any]] = []

        for file_path in file_list:
            try:
                self.logger.info("Analyzing %s (%d/%d)", file_path, len(results) + 1, len(file_list))
                result = self.analyze_binary(file_path, options)
                results.append(result)
            except Exception as e:
                self.logger.exception("Failed to analyze %s: %s", file_path, e)
                results.append(
                    {
                        "target_file": file_path,
                        "error": str(e),
                        "timestamp": datetime.datetime.now().isoformat(),
                    },
                )

        return results


def main() -> None:
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
        if args.batch or Path(args.target).is_dir():
            # Batch mode
            target_dir = Path(args.target)

            if not target_dir.exists():
                logger.error("Directory not found: %s", args.target)
                sys.exit(1)

            # Collect files
            file_list: list[str] = []
            for ext in args.extensions:
                if args.recursive:
                    file_list.extend(str(f) for f in target_dir.rglob(f"*{ext}"))
                else:
                    file_list.extend(str(f) for f in target_dir.glob(f"*{ext}"))

            if not file_list:
                logger.error("No files found with extensions: %s", args.extensions)
                sys.exit(1)

            logger.info("Found %d files to analyze", len(file_list))

            # Run batch analysis
            results = cli.run_batch_analysis(file_list, options)

            if args.json_output:
                logger.info("%s", json.dumps(results, indent=2))
            else:
                # Generate batch report
                for i, result in enumerate(results):
                    if "error" not in result:
                        output_file = f"report_{i + 1}_{Path(result['target_file']).stem}.{args.format}"
                        cli.generate_report(result, args.format, output_file)

                logger.info("Analysis complete. %d files processed.", len(results))

        else:
            # Single file mode
            if not os.path.exists(args.target):
                logger.error("File not found: %s", args.target)
                sys.exit(1)

            # Run analysis
            result = cli.analyze_binary(args.target, options)

            if args.json_output:
                logger.info("%s", json.dumps(result, indent=2))
            else:
                # Generate report
                report_path = cli.generate_report(result, args.format, args.output)
                logger.info("Analysis complete. Report saved to: %s", report_path)

    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception("Error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
