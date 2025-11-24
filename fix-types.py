#!/usr/bin/env python3
"""Shortcut to run Claude Type Fixer (Parallel).

Usage:
    python fix-types.py
    python fix-types.py --max-workers 10
    python fix-types.py --help
"""

import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Execute the parallel type fixer script."""
    script_path = Path(__file__).parent / "scripts" / "claude_type_fixer.py"

    if not script_path.exists():
        print(f"❌ Script not found: {script_path}")
        sys.exit(1)

    args = sys.argv[1:]

    try:
        subprocess.run(["python", str(script_path), *args], check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
