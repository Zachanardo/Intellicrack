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
Fix dependency conflicts by installing compatible versions
"""
import subprocess
import sys

def run_pip(args):
    """Run pip command and return success status"""
    try:
        result = subprocess.run([sys.executable, "-m", "pip"] + args, 
                              capture_output=True, text=True, check=True)
        print(f"✓ {' '.join(args)}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {' '.join(args)}")
        print(f"Error: {e.stderr}")
        return False

def main():
    print("Fixing Intellicrack dependency conflicts...")

    # Step 1: Uninstall conflicting packages
    print("\n1. Removing conflicting packages...")
    run_pip(["uninstall", "langchain-core", "langsmith", "-y"])

    # Step 2: Install python-fx for qiling
    print("\n2. Installing python-fx for qiling...")
    run_pip(["install", "python-fx==0.3.2"])

    # Step 3: Install compatible versions
    print("\n3. Installing compatible package versions...")

    # Fix click version for safety
    run_pip(["install", "click>=8.0.2,<8.2.0"])

    # Fix anthropic with compatible httpx
    run_pip(["install", "httpx>=0.25.0,<1.0"])
    run_pip(["install", "anthropic>=0.54.0"])

    # Ensure mitmproxy still works
    run_pip(["install", "--force-reinstall", "mitmproxy>=9.0.1,<10.0.0"])

    print("\n4. Testing imports...")
    try:
        import intellicrack
        print("✓ intellicrack imports successfully")
    except Exception as e:
        print(f"✗ intellicrack import failed: {e}")

    try:
        import mitmproxy
        print("✓ mitmproxy imports successfully")
    except Exception as e:
        print(f"✗ mitmproxy import failed: {e}")

    try:
        import qiling
        print("✓ qiling imports successfully")
    except Exception as e:
        print(f"✗ qiling import failed: {e}")

    try:
        import anthropic
        print("✓ anthropic imports successfully")
    except Exception as e:
        print(f"✗ anthropic import failed: {e}")

    print("\nDependency fix complete!")

if __name__ == "__main__":
    main()