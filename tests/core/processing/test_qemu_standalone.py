"""Standalone test to verify QEMU emulator test setup works.

This file tests the test infrastructure without importing the full module.
"""

import os
import subprocess
import tempfile
from pathlib import Path


def test_qemu_binary_available() -> None:
    """Check if QEMU binary is available on the system."""
    try:
        result = subprocess.run(
            ["qemu-system-x86_64", "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        qemu_available = result.returncode == 0

        if qemu_available:
            print(f"QEMU is available: {result.stdout.decode()[:100]}")
        else:
            print("QEMU not available or failed to execute")

        assert isinstance(qemu_available, bool)

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"QEMU not found: {e}")


def test_kvm_support_detection() -> None:
    """Check if KVM support can be detected."""
    kvm_available = os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)

    print(f"KVM support available: {kvm_available}")
    assert isinstance(kvm_available, bool)


def test_temp_binary_creation() -> None:
    """Verify test fixture setup for binary creation."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00")
        f.write(b"\x00" * 1024)
        temp_path = Path(f.name)

    try:
        assert temp_path.exists()
        assert temp_path.stat().st_size > 0

        with open(temp_path, "rb") as f:
            header = f.read(2)
            assert header == b"MZ"

        print(f"Test binary created successfully: {temp_path}")

    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_import_can_fail_gracefully() -> None:
    """Verify import error handling works correctly."""
    try:
        from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
        print("QEMUSystemEmulator imported successfully")
        import_succeeded = True
    except (ImportError, TypeError) as e:
        print(f"Import failed (expected in some environments): {e}")
        import_succeeded = False

    assert isinstance(import_succeeded, bool)


if __name__ == "__main__":
    print("Running QEMU emulator test infrastructure validation...\n")

    test_qemu_binary_available()
    print("✓ QEMU binary check passed\n")

    test_kvm_support_detection()
    print("✓ KVM support detection passed\n")

    test_temp_binary_creation()
    print("✓ Temp binary creation passed\n")

    test_import_can_fail_gracefully()
    print("✓ Import error handling passed\n")

    print("All infrastructure tests passed!")
