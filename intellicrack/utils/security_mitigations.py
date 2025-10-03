"""Security mitigations for known vulnerabilities in dependencies.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def mitigate_future_vulnerability() -> None:
    """Mitigate CVE GHSA-xqrq-4mgf-ff32 in future package.

    The future package (0.14.0+) automatically imports test.py files
    if present in the same directory or sys.path, allowing arbitrary
    code execution. This mitigation prevents that behavior.
    """
    try:
        import builtins

        original_import = builtins.__import__

        def secure_import(name, *args, **kwargs):
            """Wrapper to prevent automatic import of test.py by future package."""
            if name == "test" and len(args) > 0 and args[0] is not None:
                fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist", ())
                level = args[3] if len(args) > 3 else kwargs.get("level", 0)

                caller_globals = args[0]
                if caller_globals and "__name__" in caller_globals:
                    caller_module = caller_globals["__name__"]

                    if "future" in caller_module or "nampa" in caller_module:
                        logger.warning(
                            f"Blocked potential exploitation attempt: future/nampa tried to import 'test' module from {caller_module}"
                        )
                        return type(sys)("test")

            return original_import(name, *args, **kwargs)

        builtins.__import__ = secure_import
        logger.info("Future package vulnerability mitigation applied (GHSA-xqrq-4mgf-ff32)")

    except Exception as e:
        logger.error(f"Failed to apply future vulnerability mitigation: {e}")


def scan_for_malicious_test_files() -> list[Path]:
    """Scan for potentially malicious test.py files in dangerous locations.

    Returns:
        List of suspicious test.py file paths found
    """
    suspicious_files = []

    dangerous_paths = [
        Path.cwd(),
        Path(sys.prefix) / "Lib" / "site-packages",
        *[Path(p) for p in sys.path if p and os.path.exists(p)],
    ]

    for base_path in dangerous_paths:
        try:
            test_file = base_path / "test.py"
            if test_file.exists() and test_file.is_file():
                with open(test_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1000)

                    suspicious_patterns = [
                        "exec(",
                        "eval(",
                        "__import__",
                        "subprocess",
                        "os.system",
                        "socket",
                        "requests",
                        "ctypes",
                        "win32api",
                    ]

                    if any(pattern in content for pattern in suspicious_patterns):
                        suspicious_files.append(test_file)
                        logger.warning(f"Found suspicious test.py at {test_file} - potential future package vulnerability exploit")
        except (OSError, PermissionError) as e:
            logger.debug(f"Could not scan {base_path}: {e}")

    return suspicious_files


def remove_malicious_test_files(files: list[Path], force: bool = False) -> int:
    """Remove potentially malicious test.py files.

    Args:
        files: List of file paths to remove
        force: If True, remove without confirmation

    Returns:
        Number of files successfully removed
    """
    removed = 0

    for file_path in files:
        try:
            if force or _is_safe_to_remove(file_path):
                file_path.unlink()
                logger.info(f"Removed suspicious test.py: {file_path}")
                removed += 1
            else:
                logger.warning(f"Skipped removal of {file_path} - may be legitimate")
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to remove {file_path}: {e}")

    return removed


def _is_safe_to_remove(file_path: Path) -> bool:
    """Check if a test.py file is safe to remove.

    Args:
        file_path: Path to test.py file

    Returns:
        True if file appears to be malicious/unwanted
    """
    try:
        if not file_path.name == "test.py":
            return False

        parent = file_path.parent.name

        legitimate_test_dirs = ["tests", "test", "testing", "unittest", "pytest", "specs", "spec", "__pycache__"]

        if any(test_dir in parent.lower() for test_dir in legitimate_test_dirs):
            return False

        if file_path.stat().st_size < 50:
            return True

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            first_lines = f.read(500)
            if "unittest" in first_lines or "pytest" in first_lines:
                return False
            if "#!/usr/bin/env python" not in first_lines:
                return True

    except Exception as e:
        logger.debug(f"Error checking safety of {file_path}: {e}")
        return False

    return False


def apply_all_mitigations() -> dict[str, bool]:
    """Apply all available security mitigations.

    Returns:
        Dictionary mapping mitigation names to success status
    """
    results = {}

    mitigate_future_vulnerability()
    results["future_vulnerability_mitigation"] = True

    suspicious_files = scan_for_malicious_test_files()
    if suspicious_files:
        removed = remove_malicious_test_files(suspicious_files)
        results["malicious_test_files_removed"] = removed
        logger.warning(f"Found and removed {removed} suspicious test.py files")
    else:
        results["malicious_test_files_removed"] = 0

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = apply_all_mitigations()
    print(f"Security mitigations applied: {results}")
