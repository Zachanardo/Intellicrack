#!/usr/bin/env python
"""Debug script to trace Intellicrack launch issues."""

import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")

print("Starting Intellicrack import debug...")

try:
    print("1. Importing logger...")
    from intellicrack.utils.logger import logger
    print("   ✓ Logger imported")

    print("2. Importing config...")
    from intellicrack import config
    print("   ✓ Config imported")

    print("3. Importing CLI...")
    from intellicrack.cli import cli
    print("   ✓ CLI imported")

    print("4. Creating argument namespace...")
    import argparse
    args = argparse.Namespace(
        gui=True,
        file=None,
        command=None,
        verbose=False,
        debug=False,
        output=None,
        config=None
    )
    print("   ✓ Args created")

    print("5. Calling cli.main with GUI flag...")
    cli.main(args)
    print("   ✓ CLI main completed")

except Exception as e:
    import traceback
    print(f"\n❌ Error during launch: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
