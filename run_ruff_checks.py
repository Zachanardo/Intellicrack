#!/usr/bin/env python3
"""Script to run comprehensive Ruff checks based on the configured rules.

This script demonstrates how Ruff can replace multiple linting tools
that were previously configured separately in the project.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path


def run_command(cmd: str, description: str) -> bool:
    """Run a command and return True if successful, False otherwise."""
    print(f"\n{description}")
    print(f"Command: {cmd}")

    try:
        result = subprocess.run(
            shlex.split(cmd),
            shell=False,
            capture_output=True,
            text=True,
            cwd=os.getcwd()
        )

        if result.stdout:
            print("STDOUT:", result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        success = result.returncode == 0
        print(f"Success: {success}")
        return success
    except Exception as e:
        print(f"Error running command: {e!s}")
        return False


def main():
    """Main function to demonstrate Ruff capabilities."""
    print("Intellicrack: Comprehensive Ruff Configuration")
    print("="*50)

    # Check if Ruff is installed
    ruff_check = run_command('python -c "import ruff"', "Checking if Ruff is available in Python environment")

    if not ruff_check:
        print("\nRuff is not directly importable. Checking if it's available as CLI tool...")
        ruff_cli_check = run_command("ruff --version", "Checking Ruff CLI availability")

        if not ruff_cli_check:
            print("\nRuff is not available in the current environment.")
            print("You can install it with: pip install ruff")
            print("Or run in the project environment where it's already listed in dependencies.")
            return 1

    print("\n" + "="*50)
    print("Running Ruff checks - replacing multiple linting tools:")
    print("- flake8 (with plugins like flake8-bugbear, flake8-comprehensions, etc.)")
    print("- pycodestyle")
    print("- pyflakes")
    print("- isort")
    print("- mccabe")
    print("- pylint")
    print("- pyupgrade")
    print("- pydocstyle")
    print("- bandit")
    print("- autoflake")
    print("- and many more")

    # Run Ruff lint check
    run_command(
        "ruff check intellicrack/",
        "Running Ruff lint checks (replaces flake8, pycodestyle, pyflakes, etc.)"
    )

    # Run Ruff formatting check (like Black but can be configured to auto-fix)
    run_command(
        "ruff format intellicrack/ --check",
        "Running Ruff formatting check (replaces Black-style formatting)"
    )

    # Run Ruff with auto-fix (for safe changes)
    print("\nTo auto-fix issues, you can run:")
    print("ruff check intellicrack/ --fix")

    # Show what linters are available
    run_command(
        "ruff linter",
        "Showing all available Ruff linters"
    )

    print("\n" + "="*50)
    print("Ruff configuration successfully replaces the following tools:")
    print("✓ flake8 + plugins (bugbear, comprehensions, etc.)")
    print("✓ pycodestyle")
    print("✓ pyflakes")
    print("✓ isort")
    print("✓ mccabe (complexity checking)")
    print("✓ pylint")
    print("✓ pyupgrade")
    print("✓ pydocstyle")
    print("✓ bandit (security checks)")
    print("✓ autoflake")
    print("✓ many other linting/formatter tools")
    print("\nThe configuration allows for project-specific settings needed for")
    print("binary analysis tools, including security research requirements.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
