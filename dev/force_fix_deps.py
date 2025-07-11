#!/usr/bin/env python3
"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Force install correct package versions for mitmproxy compatibility
"""
import subprocess
import sys

def force_install(package, version):
    """Force install a specific package version"""
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            f"{package}=={version}", "--force-reinstall", "--no-deps"
        ], check=True)
        print(f"✓ Forced {package}=={version}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install {package}=={version}")
        return False

def main():
    print("Force fixing dependency versions for mitmproxy compatibility...")

    # Force mitmproxy-compatible versions
    force_install("h11", "0.14.0")
    force_install("click", "8.1.7")
    force_install("zstandard", "0.19.0")
    force_install("pyperclip", "1.8.2")
    force_install("urwid", "2.1.2")

    # Reinstall mitmproxy to ensure it works
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "mitmproxy==9.0.1", "--force-reinstall"
        ], check=True)
        print("✓ mitmproxy reinstalled")
    except:
        print("✗ mitmproxy reinstall failed")

    # Test critical imports
    print("\nTesting critical imports:")
    try:
        import mitmproxy
        print("✓ mitmproxy works")
    except Exception as e:
        print(f"✗ mitmproxy failed: {e}")

    try:
        import intellicrack
        print("✓ intellicrack works")
    except Exception as e:
        print(f"✗ intellicrack failed: {e}")

if __name__ == "__main__":
    main()