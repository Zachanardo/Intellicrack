"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

from intellicrack.utils.logger import logger


def setup_cli_logging(verbose: bool = False) -> None:
    """Configure logging for CLI usage.

    Args:
        verbose: Enable verbose logging output

    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(name)s: %(message)s", stream=sys.stdout)


def validate_binary_path(path: str) -> Path:
    """Validate binary file path and accessibility.

    Args:
        path: Path to binary file

    Returns:
        Validated Path object

    Raises:
        FileNotFoundError: If binary file doesn't exist
        PermissionError: If file is not readable

    """
    binary_path = Path(path).resolve()

    if not binary_path.exists():
        raise FileNotFoundError(f"Binary file not found: {binary_path}")

    if not binary_path.is_file():
        raise ValueError(f"Path is not a file: {binary_path}")

    if not os.access(binary_path, os.R_OK):
        raise PermissionError(f"Cannot read binary file: {binary_path}")

    return binary_path


def run_basic_analysis(binary_path: Path, options: Dict[str, Any]) -> Dict[str, Any]:
    """Perform basic binary analysis via CLI.

    Args:
        binary_path: Path to binary file for analysis
        options: Analysis configuration options

    Returns:
        Dictionary containing analysis results

    """
    try:
        # Import analysis components
        from intellicrack.core.analysis.analysis_orchestrator import AnalysisOrchestrator
        from intellicrack.core.processing.memory_loader import MemoryLoader

        logger.info(f"Starting analysis of: {binary_path}")

        # Initialize components
        orchestrator = AnalysisOrchestrator()
        memory_loader = MemoryLoader()

        # Load binary into memory
        logger.info("Loading binary into memory...")
        memory_data = memory_loader.load_binary(str(binary_path))

        # Configure analysis based on options
        analysis_config = {
            "binary_path": str(binary_path),
            "enable_entropy": options.get("entropy", True),
            "enable_strings": options.get("strings", True),
            "enable_sections": options.get("sections", True),
            "enable_imports": options.get("imports", True),
            "enable_exports": options.get("exports", True),
        }

        # Perform analysis
        logger.info("Performing binary analysis...")
        results = orchestrator.analyze_binary(**analysis_config)

        # Add memory analysis results
        if memory_data:
            from intellicrack.core.processing.memory_loader import run_memory_optimized_analysis

            memory_analysis = run_memory_optimized_analysis(binary_path=str(binary_path), **options)
            results["memory_analysis"] = memory_analysis

        logger.info("Analysis completed successfully")
        return results

    except ImportError as e:
        logger.error(f"Failed to import analysis components: {e}")
        return {"error": f"Import error: {e}"}

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return {"error": f"Analysis error: {e}"}


def format_analysis_output(results: Dict[str, Any], output_format: str) -> str:
    """Format analysis results for output.

    Args:
        results: Analysis results dictionary
        output_format: Output format ('json', 'text', 'summary')

    Returns:
        Formatted output string

    """
    if output_format.lower() == "json":
        import json

        return json.dumps(results, indent=2, default=str)

    elif output_format.lower() == "summary":
        lines = [
            "=== INTELLICRACK ANALYSIS SUMMARY ===",
            f"Binary: {results.get('binary_path', 'Unknown')}",
            f"File Size: {results.get('file_size', 'Unknown')} bytes",
            f"Architecture: {results.get('architecture', 'Unknown')}",
            f"Format: {results.get('format', 'Unknown')}",
        ]

        # Add section information
        if "sections" in results:
            lines.append(f"Sections: {len(results['sections'])}")

        # Add entropy information
        if "entropy" in results:
            entropy_data = results["entropy"]
            if isinstance(entropy_data, dict):
                lines.append(f"Entropy: {entropy_data.get('average', 'Unknown')}")

        # Add strings information
        if "strings" in results:
            strings_data = results["strings"]
            if isinstance(strings_data, list):
                lines.append(f"Strings Found: {len(strings_data)}")

        # Add memory analysis
        if "memory_analysis" in results:
            lines.append("Memory Analysis: Completed")

        # Add any errors
        if "error" in results:
            lines.append(f"Error: {results['error']}")

        return "\n".join(lines)

    else:  # text format
        lines = ["=== INTELLICRACK DETAILED ANALYSIS ==="]
        for key, value in results.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{key.upper()}:")
                lines.append(f"  {str(value)}")
            else:
                lines.append(f"{key.upper()}: {value}")
        return "\n".join(lines)


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command line argument parser.

    Returns:
        Configured ArgumentParser instance

    """
    parser = argparse.ArgumentParser(
        description="Intellicrack Binary Analysis CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s binary.exe                    # Basic analysis
  %(prog)s binary.exe -v                # Verbose output
  %(prog)s binary.exe -o json           # JSON output format
  %(prog)s binary.exe --no-entropy      # Disable entropy analysis
  %(prog)s binary.exe --output results.json  # Save to file
        """,
    )

    parser.add_argument("binary", help="Path to binary file for analysis")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging output")

    parser.add_argument("-o", "--format", choices=["text", "json", "summary"], default="summary", help="Output format (default: summary)")

    parser.add_argument("--output", metavar="FILE", help="Save results to file instead of stdout")

    parser.add_argument("--no-entropy", action="store_true", help="Disable entropy analysis")

    parser.add_argument("--no-strings", action="store_true", help="Disable string extraction")

    parser.add_argument("--no-sections", action="store_true", help="Disable section analysis")

    parser.add_argument("--no-imports", action="store_true", help="Disable import analysis")

    parser.add_argument("--no-exports", action="store_true", help="Disable export analysis")

    return parser


def main() -> int:
    """Main CLI entry point.

    Returns:
        Exit code (0 for success, 1 for error)

    """
    try:
        parser = create_cli_parser()
        args = parser.parse_args()

        # Setup logging
        setup_cli_logging(args.verbose)

        logger.info("Intellicrack CLI Analysis Tool")

        # Validate binary path
        try:
            binary_path = validate_binary_path(args.binary)
        except (FileNotFoundError, PermissionError, ValueError) as e:
            logger.error(f"Binary validation failed: {e}")
            return 1

        # Configure analysis options
        options = {
            "entropy": not args.no_entropy,
            "strings": not args.no_strings,
            "sections": not args.no_sections,
            "imports": not args.no_imports,
            "exports": not args.no_exports,
            "verbose": args.verbose,
        }

        # Run analysis
        results = run_basic_analysis(binary_path, options)

        # Format output
        output = format_analysis_output(results, args.format)

        # Save or print results
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                logger.info(f"Results saved to: {args.output}")
            except IOError as e:
                logger.error(f"Failed to save results: {e}")
                return 1
        else:
            print(output)

        # Check for analysis errors
        if "error" in results:
            logger.warning("Analysis completed with errors")
            return 1

        logger.info("Analysis completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 1

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            import traceback

            logger.debug(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
