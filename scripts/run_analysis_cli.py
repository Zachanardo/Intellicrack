"""
Command-line interface for Intellicrack binary analysis. 

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

#!/usr/bin/env python3
"""
Command-line interface for Intellicrack binary analysis.

This script provides a CLI interface for running various analysis operations
on binary files without launching the full GUI application.
"""

import os
import sys
import argparse
import json
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from intellicrack.utils.binary_analysis import analyze_binary
    from intellicrack.utils.runner_functions import (
        run_comprehensive_analysis,
        run_deep_license_analysis,
        run_detect_packing,
        run_vulnerability_scan
    )
    from intellicrack.utils.report_generator import generate_report
    from intellicrack.config import CONFIG
except ImportError as e:
    print(f"Error importing Intellicrack modules: {e}")
    print("Please ensure Intellicrack is properly installed.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Intellicrack Binary Analysis CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s binary.exe                          # Basic analysis
  %(prog)s binary.exe --comprehensive         # Full analysis
  %(prog)s binary.exe --output report.pdf     # Generate PDF report
  %(prog)s binary.exe --format json           # JSON output
  %(prog)s binary.exe --detect-packing        # Check for packers
  %(prog)s binary.exe --license-analysis      # License mechanism analysis
        """
    )

    # Positional arguments
    parser.add_argument(
        'binary',
        help='Path to the binary file to analyze'
    )

    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument(
        '--comprehensive', '-c',
        action='store_true',
        help='Run comprehensive analysis (all modules)'
    )
    analysis_group.add_argument(
        '--detect-packing', '-p',
        action='store_true',
        help='Detect packing and obfuscation'
    )
    analysis_group.add_argument(
        '--vulnerability-scan', '-v',
        action='store_true',
        help='Scan for security vulnerabilities'
    )
    analysis_group.add_argument(
        '--license-analysis', '-l',
        action='store_true',
        help='Analyze license protection mechanisms'
    )
    analysis_group.add_argument(
        '--quick', '-q',
        action='store_true',
        help='Quick analysis (basic info only)'
    )

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    output_group.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'pdf', 'html'],
        default='text',
        help='Output format (default: text)'
    )
    output_group.add_argument(
        '--verbose', '-V',
        action='store_true',
        help='Enable verbose output'
    )
    output_group.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress non-essential output'
    )

    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        '--config',
        help='Path to custom configuration file'
    )
    advanced_group.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Analysis timeout in seconds (default: 300)'
    )
    advanced_group.add_argument(
        '--threads',
        type=int,
        default=4,
        help='Number of analysis threads (default: 4)'
    )

    return parser.parse_args()


def load_custom_config(config_path):
    """Load custom configuration from file."""
    try:
        with open(config_path, 'r') as f:
            custom_config = json.load(f)

        # Merge with default config
        CONFIG.update(custom_config)
        logger.info(f"Loaded custom configuration from {config_path}")
    except Exception as e:
        logger.error(f"Failed to load custom configuration: {e}")
        sys.exit(1)


def perform_analysis(binary_path, args):
    """Perform the requested analysis on the binary."""
    results = {
        'binary': binary_path,
        'timestamp': str(Path(binary_path).stat().st_mtime),
        'analyses': {}
    }

    try:
        if args.comprehensive:
            logger.info("Running comprehensive analysis...")
            results['analyses']['comprehensive'] = run_comprehensive_analysis(
                binary_path,
                timeout=args.timeout
            )

        elif args.quick:
            logger.info("Running quick analysis...")
            results['analyses']['basic'] = analyze_binary(binary_path)

        else:
            # Run selected analyses
            if args.detect_packing:
                logger.info("Detecting packing...")
                results['analyses']['packing'] = run_detect_packing(binary_path)

            if args.vulnerability_scan:
                logger.info("Scanning for vulnerabilities...")
                results['analyses']['vulnerabilities'] = run_vulnerability_scan(binary_path)

            if args.license_analysis:
                logger.info("Analyzing license mechanisms...")
                results['analyses']['license'] = run_deep_license_analysis(binary_path)

            # If no specific analysis selected, run basic
            if not any([args.detect_packing, args.vulnerability_scan, args.license_analysis]):
                logger.info("Running basic analysis...")
                results['analyses']['basic'] = analyze_binary(binary_path)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None

    return results


def format_output(results, format_type):
    """Format the analysis results based on the requested format."""
    if format_type == 'json':
        return json.dumps(results, indent=2)

    elif format_type == 'text':
        output = []
        output.append(f"=== Intellicrack Analysis Report ===")
        output.append(f"Binary: {results['binary']}")
        output.append(f"Timestamp: {results['timestamp']}")
        output.append("")

        for analysis_type, data in results['analyses'].items():
            output.append(f"--- {analysis_type.upper()} ---")
            if isinstance(data, dict):
                for key, value in data.items():
                    output.append(f"{key}: {value}")
            else:
                output.append(str(data))
            output.append("")

        return '\n'.join(output)

    elif format_type in ['pdf', 'html']:
        # Use the report generator for PDF/HTML
        return generate_report(
            results,
            report_format=format_type,
            title=f"Intellicrack Analysis: {Path(results['binary']).name}"
        )

    return str(results)


def save_output(output, output_path, format_type):
    """Save the formatted output to a file."""
    try:
        if format_type == 'pdf':
            # For PDF, output is already bytes
            with open(output_path, 'wb') as f:
                f.write(output)
        else:
            # For text/json/html, output is string
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output)

        logger.info(f"Output saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save output: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    args = parse_arguments()

    # Configure logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate binary path
    if not os.path.exists(args.binary):
        logger.error(f"Binary file not found: {args.binary}")
        sys.exit(1)

    # Load custom config if provided
    if args.config:
        load_custom_config(args.config)

    # Perform analysis
    logger.info(f"Analyzing {args.binary}...")
    results = perform_analysis(args.binary, args)

    if results is None:
        logger.error("Analysis failed")
        sys.exit(1)

    # Format output
    output = format_output(results, args.format)

    # Save or print output
    if args.output:
        save_output(output, args.output, args.format)
    else:
        if args.format == 'pdf':
            logger.error("PDF output requires --output flag")
            sys.exit(1)
        print(output)

    logger.info("Analysis complete")
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)