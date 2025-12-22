"""Interactive CLI mode for Intellicrack.

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

import cmd
import sys
from pathlib import Path
from typing import Any, TYPE_CHECKING


# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.logger import get_logger
from intellicrack.utils.runtime.runner_functions import run_comprehensive_analysis

if TYPE_CHECKING:
    from intellicrack.cli.ai_chat_interface import AITerminalChat


logger = get_logger(__name__)


class IntellicrackShell(cmd.Cmd):
    """Interactive command shell for Intellicrack."""

    intro = """
    ╔══════════════════════════════════════════════════════════════╗
    ║           Intellicrack Interactive Shell v1.0.0              ║
    ║     Advanced Binary Analysis & Security Research Platform    ║
    ╚══════════════════════════════════════════════════════════════╝

    Type 'help' for available commands or 'exit' to quit.
    """

    prompt = "intellicrack> "

    def __init__(self) -> None:
        """Initialize the interactive shell."""
        super().__init__()
        self.current_file: Path | None = None
        self.analysis_results: dict[str, Any] | None = None
        self.ai_chat: AITerminalChat | None = None

    def do_load(self, arg: str) -> None:
        """Load a binary file for analysis: load <filepath>."""
        if not arg:
            logger.warning("Usage: load <filepath>")
            return

        filepath = Path(arg)
        if not filepath.exists():
            logger.exception("File not found: %s", arg)
            return

        self.current_file = filepath
        logger.info("Loaded: %s", filepath)

    def do_analyze(self, arg: str) -> None:
        """Analyze the currently loaded file."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        try:
            logger.info("Analyzing %s...", self.current_file)
            self.analysis_results = run_comprehensive_analysis(str(self.current_file))
            logger.info("Analysis complete!")
        except Exception as e:
            logger.exception("Analysis failed: %s", e, exc_info=True)

    def do_status(self, arg: str) -> None:
        """Show current status."""
        logger.info("Current file: %s", self.current_file or "None")
        logger.info("Analysis results: %s", "Available" if self.analysis_results else "None")

    def do_clear(self, arg: str) -> None:
        """Clear current session."""
        self.current_file = None
        self.analysis_results = None
        logger.info("Session cleared")

    def do_exit(self, arg: str) -> bool:
        """Exit the interactive shell."""
        logger.info("Goodbye!")
        return True

    def do_quit(self, arg: str) -> bool:
        """Exit the interactive shell."""
        return self.do_exit(arg)

    def do_scan(self, arg: str) -> None:
        """Scan for vulnerabilities: scan [--vulns]."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        try:
            from intellicrack.core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine

            logger.info("Scanning %s for vulnerabilities...", self.current_file)
            vulnerabilities = AdvancedVulnerabilityEngine.scan_binary(str(self.current_file))

            if vulnerabilities:
                logger.info("Found %d vulnerabilities:", len(vulnerabilities))
                for vuln in vulnerabilities:
                    logger.info("  - %s: %s", vuln.get("type", "Unknown"), vuln.get("description", "No description"))
                    logger.info("    Severity: %s", vuln.get("severity", "Unknown"))
            else:
                logger.info("No vulnerabilities found.")

        except Exception as e:
            logger.exception("Scan failed: %s", e, exc_info=True)

    def do_strings(self, arg: str) -> None:
        """Extract strings from the loaded file: strings [min_length]."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        try:
            min_length = int(arg) if arg else 4

            from intellicrack.cli.analysis_cli import AnalysisCLI

            logger.info("Extracting strings (min length: %d)...", min_length)
            if strings := AnalysisCLI._extract_strings(str(self.current_file), min_length):
                logger.info("Found %d strings:", len(strings))
                for s in strings[:50]:
                    logger.info("  %s", s)
                if len(strings) > 50:
                    logger.info("  ... and %d more", len(strings) - 50)
            else:
                logger.info("No strings found.")

        except Exception as e:
            logger.exception("String extraction failed: %s", e, exc_info=True)

    def do_export(self, arg: str) -> None:
        """Export analysis results: export <format> <output_file>."""
        if not self.analysis_results:
            logger.exception("No analysis results. Run 'analyze' first.")
            return

        parts = arg.split()
        if len(parts) < 2:
            logger.warning("Usage: export <format> <output_file>")
            logger.info("Formats: json, html, pdf, csv")
            return

        format_type = parts[0].lower()
        output_file = " ".join(parts[1:])

        try:
            from intellicrack.cli.advanced_export import AdvancedExporter

            if not self.current_file:
                logger.exception("No binary file loaded. Use 'load <filepath>' to load a binary first.")
                return

            if not self.analysis_results:
                logger.exception("No analysis results available. Run 'analyze' on a loaded binary first.")
                return

            binary_path = str(self.current_file)
            exporter = AdvancedExporter(binary_path, self.analysis_results)

            success = False
            if format_type == "json":
                success = exporter.export_detailed_json(output_file)
            elif format_type == "html":
                success = exporter.export_html_report(output_file)
            elif format_type == "xml":
                success = exporter.export_xml_report(output_file)
            elif format_type == "csv":
                success = exporter.export_csv_data(output_file)
            elif format_type in {"excel", "xlsx"}:
                success = exporter.export_excel_workbook(output_file)
            elif format_type == "yaml":
                success = exporter.export_yaml_config(output_file)
            else:
                logger.warning("Unknown format: %s", format_type)
                logger.info("Supported formats: json, html, xml, csv, excel, yaml")
                return

            if success:
                logger.info("Successfully exported to %s", output_file)
            else:
                logger.exception("Export failed - check dependencies for %s format", format_type)

        except Exception as e:
            logger.exception("Export failed: %s", e, exc_info=True)

    def do_hexview(self, arg: str) -> None:
        """Open hex viewer for the loaded file."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        try:
            import curses

            from intellicrack.cli.hex_viewer_cli import TerminalHexViewer

            viewer = TerminalHexViewer(str(self.current_file))
            curses.wrapper(viewer.run)

        except Exception as e:
            logger.exception("Hex viewer failed: %s", e, exc_info=True)

    def do_protection(self, arg: str) -> None:
        """Analyze protection mechanisms."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        try:
            from intellicrack.protection.protection_detector import detect_all_protections as analyze_protections

            logger.info("Analyzing protections in %s...", self.current_file)
            if protections := analyze_protections(str(self.current_file)):
                logger.info("Detected protections:")
                for protection, details in protections.items():
                    if details.get("detected"):
                        logger.info("  - %s: %s", protection, details.get("type", "Unknown type"))
                        if details.get("confidence"):
                            logger.info("    Confidence: %d%%", details["confidence"])
            else:
                logger.info("No protections detected.")

        except Exception as e:
            logger.exception("Protection analysis failed: %s", e, exc_info=True)

    def do_patch(self, arg: str) -> None:
        """Generate patches for the loaded file: patch <output_file>."""
        if not self.current_file:
            logger.exception("No file loaded. Use 'load' command first.")
            return

        if not arg:
            logger.warning("Usage: patch <output_file>")
            return

        try:
            from intellicrack.utils.patching.patch_generator import generate_patch

            logger.info("Generating patches for %s...", self.current_file)
            patches = generate_patch(str(self.current_file))

            if patches and patches.get("patches"):
                import json

                with open(arg, "w") as f:
                    json.dump(patches, f, indent=2)

                logger.info("Generated %d patches", len(patches["patches"]))
                logger.info("Patches saved to: %s", arg)
            else:
                logger.info("No patches generated.")

        except Exception as e:
            logger.exception("Patch generation failed: %s", e, exc_info=True)

    def do_ai(self, arg: str) -> None:
        """Interact with AI assistant: ai <question>."""
        if not arg:
            logger.warning("Usage: ai <question>")
            return

        try:
            from intellicrack.cli.ai_chat_interface import AITerminalChat

            if self.ai_chat is None:
                self.ai_chat = AITerminalChat(
                    binary_path=str(self.current_file) if self.current_file else None,
                    analysis_results=self.analysis_results
                )

            response = self.ai_chat._get_ai_response(arg)
            logger.info("AI: %s", response)

        except Exception as e:
            logger.exception("AI assistant error: %s", e, exc_info=True)

    def do_help(self, arg: str) -> None:
        """Show help for commands."""
        if arg:
            super().do_help(arg)
        else:
            logger.info("Available commands:")
            logger.info("[File Operations]")
            logger.info("  load <file>      - Load a binary file for analysis")
            logger.info("  clear            - Clear current session")
            logger.info("  status           - Show current status")

            logger.info("[Analysis]")
            logger.info("  analyze          - Comprehensive analysis of loaded file")
            logger.info("  scan [--vulns]   - Scan for vulnerabilities")
            logger.info("  strings [len]    - Extract strings (optional min length)")
            logger.info("  protection       - Analyze protection mechanisms")
            logger.info("  hexview          - Open interactive hex viewer")

            logger.info("[Export & Patching]")
            logger.info("  export <fmt> <f> - Export results (json/html/pdf/csv)")
            logger.info("  patch <output>   - Generate patches")

            logger.info("[AI & Help]")
            logger.info("  ai <question>    - Ask AI assistant")
            logger.info("  help [cmd]       - Show help")
            logger.info("  exit/quit        - Exit the shell")


def main() -> int:
    """Launch interactive mode."""
    shell = IntellicrackShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        logger.warning("Interrupted. Use 'exit' to quit properly.")
        return main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
