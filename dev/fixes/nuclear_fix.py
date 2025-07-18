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
Nuclear option: Force install everything with --no-deps to bypass conflicts
"""
import subprocess
import sys

def force_install_no_deps(packages):
    """Install packages with --no-deps to bypass conflicts"""
    for package in packages:
        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                package, "--force-reinstall", "--no-deps"
            ], check=True)
            print(f"✓ {package}")
        except subprocess.CalledProcessError:
            print(f"✗ {package}")

def main():
    print("Nuclear dependency fix - installing everything with --no-deps...")

    # Core packages for mitmproxy compatibility
    mitmproxy_packages = [
        "h11==0.14.0",
        "zstandard==0.19.0",
        "pyperclip==1.8.2",
        "urwid==2.1.2",
        "cryptography==38.0.4",
        "pyopenssl==22.1.0"
    ]

    # Core packages for python-fx/qiling
    qiling_packages = [
        "click==8.1.7",
        # Don't force pyperclip/urwid versions - let qiling adapt
    ]

    # Essential Intellicrack packages
    essential_packages = [
        "capstone==5.0.1",
        "lief",
        "matplotlib",
        "tensorflow-cpu",
        "pandas",
        "scikit-learn",
        "reportlab",
        "python-dotenv",
        "aiohttp",
        "scapy",
        "pdfkit",
        "flask-cors",
        "transformers",
        "peft"
    ]

    print("\n1. Installing mitmproxy compatible versions...")
    force_install_no_deps(mitmproxy_packages)

    print("\n2. Installing qiling compatible versions...")
    force_install_no_deps(qiling_packages)

    print("\n3. Installing essential packages...")
    force_install_no_deps(essential_packages)

    # Now install main packages normally
    print("\n4. Installing main packages...")
    main_packages = ["mitmproxy==9.0.1", "python-fx==0.3.2", "qiling", "anthropic"]
    for pkg in main_packages:
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=True)
            print(f"✓ {pkg}")
        except:
            print(f"✗ {pkg}")

    print("\n5. Testing imports...")
    test_imports = ["intellicrack", "mitmproxy", "qiling", "anthropic", "capstone", "lief"]
    for module in test_imports:
        try:
            __import__(module)
            print(f"✓ {module}")
        except Exception as e:
            print(f"✗ {module}: {e}")

if __name__ == "__main__":
    main()
