#!/usr/bin/env python3
"""
Intellicrack Launcher
Launch the Intellicrack application with proper environment setup.
"""

import sys
from pathlib import Path

def main():
    # Add the intellicrack package to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))

    try:
        # Import and run the main application
        from intellicrack.main import main as intellicrack_main
        intellicrack_main()
    except ImportError as e:
        print(f"ERROR: Failed to import Intellicrack: {e}")
        print("Make sure all dependencies are installed.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start Intellicrack: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
