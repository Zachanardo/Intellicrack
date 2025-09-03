"""Interactive CLI mode for Intellicrack.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import cmd
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.logger import get_logger
from intellicrack.utils.runner_functions import run_comprehensive_analysis

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

    def __init__(self):
        """Initialize the interactive shell."""
        super().__init__()
        self.current_file = None
        self.analysis_results = None

    def do_load(self, arg):
        """Load a binary file for analysis: load <filepath>."""
        if not arg:
            print("Usage: load <filepath>")
            return

        filepath = Path(arg)
        if not filepath.exists():
            print(f"Error: File not found: {arg}")
            return

        self.current_file = filepath
        print(f"Loaded: {filepath}")

    def do_analyze(self, arg):
        """Analyze the currently loaded file."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        try:
            print(f"Analyzing {self.current_file}...")
            self.analysis_results = run_comprehensive_analysis(str(self.current_file), verbose=True)
            print("Analysis complete!")
        except Exception as e:
            print(f"Analysis failed: {e}")

    def do_status(self, arg):
        """Show current status."""
        print(f"Current file: {self.current_file or 'None'}")
        print(f"Analysis results: {'Available' if self.analysis_results else 'None'}")

    def do_clear(self, arg):
        """Clear current session."""
        self.current_file = None
        self.analysis_results = None
        print("Session cleared")

    def do_exit(self, arg):
        """Exit the interactive shell."""
        print("Goodbye!")
        return True

    def do_quit(self, arg):
        """Exit the interactive shell."""
        return self.do_exit(arg)

    def do_scan(self, arg):
        """Scan for vulnerabilities: scan [--vulns]."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        try:
            from intellicrack.core.analysis.vulnerability_engine import run_vulnerability_scan

            print(f"Scanning {self.current_file} for vulnerabilities...")
            results = run_vulnerability_scan(str(self.current_file))

            if results and results.get("vulnerabilities"):
                print(f"\nFound {len(results['vulnerabilities'])} vulnerabilities:")
                for vuln in results["vulnerabilities"]:
                    print(f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                    print(f"    Severity: {vuln.get('severity', 'Unknown')}")
            else:
                print("No vulnerabilities found.")

        except Exception as e:
            print(f"Scan failed: {e}")

    def do_strings(self, arg):
        """Extract strings from the loaded file: strings [min_length]."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        try:
            min_length = int(arg) if arg else 4

            from intellicrack.cli.analysis_cli import _extract_strings

            print(f"Extracting strings (min length: {min_length})...")
            strings = _extract_strings(str(self.current_file), min_length)

            if strings:
                print(f"\nFound {len(strings)} strings:")
                for s in strings[:50]:  # Show first 50
                    print(f"  {s}")
                if len(strings) > 50:
                    print(f"  ... and {len(strings) - 50} more")
            else:
                print("No strings found.")

        except Exception as e:
            print(f"String extraction failed: {e}")

    def do_export(self, arg):
        """Export analysis results: export <format> <output_file>."""
        if not self.analysis_results:
            print("Error: No analysis results. Run 'analyze' first.")
            return

        parts = arg.split()
        if len(parts) < 2:
            print("Usage: export <format> <output_file>")
            print("Formats: json, html, pdf, csv")
            return

        format_type = parts[0].lower()
        output_file = " ".join(parts[1:])

        try:
            from intellicrack.cli.advanced_export import AdvancedExporter

            # Use current file path or placeholder if not loaded
            binary_path = str(self.current_file) if self.current_file else "interactive_session"
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
            elif format_type == "excel" or format_type == "xlsx":
                success = exporter.export_excel_workbook(output_file)
            elif format_type == "yaml":
                success = exporter.export_yaml_config(output_file)
            else:
                print(f"Unknown format: {format_type}")
                print("Supported formats: json, html, xml, csv, excel, yaml")
                return

            if success:
                print(f"Successfully exported to {output_file}")
            else:
                print(f"Export failed - check dependencies for {format_type} format")

        except Exception as e:
            print(f"Export failed: {e}")

    def do_hexview(self, arg):
        """Open hex viewer for the loaded file."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        try:
            import curses

            from intellicrack.cli.hex_viewer_cli import TerminalHexViewer

            viewer = TerminalHexViewer(str(self.current_file))
            curses.wrapper(viewer.run)

        except Exception as e:
            print(f"Hex viewer failed: {e}")

    def do_protection(self, arg):
        """Analyze protection mechanisms."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        try:
            from intellicrack.utils.protection.protection_detection import analyze_protections

            print(f"Analyzing protections in {self.current_file}...")
            protections = analyze_protections(str(self.current_file))

            if protections:
                print("\nDetected protections:")
                for protection, details in protections.items():
                    if details.get("detected"):
                        print(f"  - {protection}: {details.get('type', 'Unknown type')}")
                        if details.get("confidence"):
                            print(f"    Confidence: {details['confidence']}%")
            else:
                print("No protections detected.")

        except Exception as e:
            print(f"Protection analysis failed: {e}")

    def do_patch(self, arg):
        """Generate patches for the loaded file: patch <output_file>."""
        if not self.current_file:
            print("Error: No file loaded. Use 'load' command first.")
            return

        if not arg:
            print("Usage: patch <output_file>")
            return

        try:
            from intellicrack.utils.patching.patch_generator import generate_patch

            print(f"Generating patches for {self.current_file}...")
            patches = generate_patch(str(self.current_file))

            if patches and patches.get("patches"):
                # Save patches to file
                import json

                with open(arg, "w") as f:
                    json.dump(patches, f, indent=2)

                print(f"Generated {len(patches['patches'])} patches")
                print(f"Patches saved to: {arg}")
            else:
                print("No patches generated.")

        except Exception as e:
            print(f"Patch generation failed: {e}")

    def do_ai(self, arg):
        """Interact with AI assistant: ai <question>."""
        if not arg:
            print("Usage: ai <question>")
            return

        try:
            from intellicrack.cli.ai_chat_interface import AIChatInterface

            # Initialize AI chat if not already done
            if not hasattr(self, "ai_chat"):
                self.ai_chat = AIChatInterface()

            # Send question and get response
            response = self.ai_chat.ask(arg, context=self.analysis_results)
            print(f"\nAI: {response}")

        except Exception as e:
            print(f"AI assistant error: {e}")

    def do_help(self, arg):
        """Show help for commands."""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            print("\nAvailable commands:")
            print("\n[File Operations]")
            print("  load <file>      - Load a binary file for analysis")
            print("  clear            - Clear current session")
            print("  status           - Show current status")

            print("\n[Analysis]")
            print("  analyze          - Comprehensive analysis of loaded file")
            print("  scan [--vulns]   - Scan for vulnerabilities")
            print("  strings [len]    - Extract strings (optional min length)")
            print("  protection       - Analyze protection mechanisms")
            print("  hexview          - Open interactive hex viewer")

            print("\n[Export & Patching]")
            print("  export <fmt> <f> - Export results (json/html/pdf/csv)")
            print("  patch <output>   - Generate patches")

            print("\n[AI & Help]")
            print("  ai <question>    - Ask AI assistant")
            print("  help [cmd]       - Show help")
            print("  exit/quit        - Exit the shell")
            print()


def main():
    """Launch interactive mode."""
    shell = IntellicrackShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Use 'exit' to quit properly.")
        return main()

    return 0


if __name__ == "__main__":
    sys.exit(main())
