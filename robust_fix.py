#!/usr/bin/env python3
"""Robust fix for all indentation issues using autopep8 with aggressive settings."""

import subprocess
import sys


def install_autopep8():
    """Install autopep8 if not available."""
    try:
        import autopep8
        return True
    except ImportError:
        print("Installing autopep8...")
        subprocess.run([sys.executable, "-m", "pip", "install", "autopep8"], check=True)
        return True

def fix_with_autopep8():
    """Use autopep8 with very aggressive settings to fix all issues."""

    file_path = 'intellicrack/ui/dialogs/vulnerability_research_dialog.py'

    # First pass - fix indentation issues
    result = subprocess.run([
        sys.executable, "-m", "autopep8",
        "--in-place",
        "--aggressive", "--aggressive", "--aggressive",  # Triple aggressive
        "--select=E1,E2,E3,W1,W2",  # Focus on indentation and whitespace
        "--max-line-length=120",
        file_path
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"autopep8 first pass error: {result.stderr}")
    else:
        print("First pass complete - fixed indentation")

    # Second pass - fix remaining issues
    result = subprocess.run([
        sys.executable, "-m", "autopep8",
        "--in-place",
        "--aggressive", "--aggressive",
        "--max-line-length=120",
        file_path
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"autopep8 second pass error: {result.stderr}")
    else:
        print("Second pass complete - fixed remaining issues")

    # Try black one more time
    result = subprocess.run([
        sys.executable, "-m", "black",
        "--line-length=120",
        "--skip-string-normalization",
        file_path
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print("Black formatting successful!")
    else:
        print(f"Black still has issues: {result.stderr}")

        # If black still fails, use isort and then autopep8 again
        print("Trying isort + autopep8 combination...")

        # Fix imports with isort
        subprocess.run([sys.executable, "-m", "pip", "install", "isort"], check=False)
        subprocess.run([sys.executable, "-m", "isort", file_path], check=False)

        # Final autopep8 pass
        subprocess.run([
            sys.executable, "-m", "autopep8",
            "--in-place",
            "--aggressive", "--aggressive",
            "--max-line-length=120",
            file_path
        ], check=False)

        print("Applied isort and final autopep8 pass")

def main():
    """Main function."""
    if install_autopep8():
        fix_with_autopep8()

        # Check if file is syntactically valid now
        result = subprocess.run([
            sys.executable, "-m", "py_compile",
            "intellicrack/ui/dialogs/vulnerability_research_dialog.py"
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print("✓ File is now syntactically valid!")
        else:
            print(f"✗ Syntax errors remain: {result.stderr}")

if __name__ == "__main__":
    main()
