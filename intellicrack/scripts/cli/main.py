"""Main CLI entry point for Intellicrack.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import argparse
import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


def create_parser():
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="intellicrack-cli",
        description="Intellicrack CLI - Advanced Binary Analysis & Security Research Platform",
        epilog="For defensive security research only. Use responsibly in controlled environments.",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Intellicrack 1.0.0",
    )
    
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Path to binary file to analyze",
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=["analyze", "exploit", "patch", "monitor"],
        default="analyze",
        help="Operation mode",
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output directory for results",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch GUI interface",
    )
    
    return parser


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.gui:
        # Launch GUI
        from intellicrack.ui.main_app import main as gui_main
        return gui_main()
    
    if args.file:
        logger.info(f"Analyzing file: {args.file}")
        # Import analysis functions
        from intellicrack.utils.runner_functions import run_comprehensive_analysis
        
        try:
            result = run_comprehensive_analysis(
                args.file,
                output_dir=args.output,
                verbose=args.verbose
            )
            logger.info("Analysis complete")
            return 0
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return 1
    
    # If no file specified, show help
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())