"""Incremental test to find crash point."""
from __future__ import annotations

import sys
import faulthandler

faulthandler.enable()


def test_step(name: str) -> None:
    """Print test step."""
    print(f"[TEST] {name}...", flush=True)


def main() -> int:
    """Run incremental tests."""
    print("=" * 60)
    print("INCREMENTAL CRASH TEST")
    print("=" * 60)

    test_step("1. Import PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication
    print("  OK")

    test_step("2. Create QApplication")
    app = QApplication(sys.argv)
    print("  OK")

    test_step("3. Import main_app")
    from intellicrack.ui import main_app
    print("  OK")

    test_step("4. Import IntellicrackApp")
    from intellicrack.ui.main_app import IntellicrackApp
    print("  OK")

    test_step("5. Create IntellicrackApp instance")
    window = IntellicrackApp()
    print("  OK")

    test_step("6. Show window")
    window.show()
    print("  OK")

    test_step("7. Process events once")
    app.processEvents()
    print("  OK")

    print("\n" + "=" * 60)
    print("All tests passed - window is now showing")
    print("Try clicking in the window...")
    print("=" * 60 + "\n")

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
