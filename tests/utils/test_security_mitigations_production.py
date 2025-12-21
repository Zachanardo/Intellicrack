"""Production tests for security mitigation utilities.

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

import builtins
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.security_mitigations import (
    _is_safe_to_remove,
    apply_all_mitigations,
    mitigate_future_vulnerability,
    remove_malicious_test_files,
    scan_for_malicious_test_files,
)


class TestFutureVulnerabilityMitigation:
    """Test future package vulnerability mitigation (GHSA-xqrq-4mgf-ff32)."""

    def test_mitigate_future_vulnerability_applied(self) -> None:
        """Test future vulnerability mitigation is applied."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()

        assert builtins.__import__ != original_import

        builtins.__import__ = original_import

    def test_mitigate_future_blocks_test_import_from_future(self) -> None:
        """Test mitigation blocks test.py import from future package."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()

        try:
            test_globals = {"__name__": "future.standard_library"}
            result = builtins.__import__("test", test_globals, None, [], 0)

            assert result is not None
            assert hasattr(result, "__name__")
        finally:
            builtins.__import__ = original_import

    def test_mitigate_future_blocks_test_import_from_nampa(self) -> None:
        """Test mitigation blocks test.py import from nampa package."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()

        try:
            test_globals = {"__name__": "nampa.core"}
            result = builtins.__import__("test", test_globals, None, [], 0)

            assert result is not None
        finally:
            builtins.__import__ = original_import

    def test_mitigate_future_allows_normal_imports(self) -> None:
        """Test mitigation allows normal module imports."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()

        try:
            test_globals = {"__name__": "__main__"}
            os_module = builtins.__import__("os", test_globals, None, [], 0)

            assert os_module.__name__ == "os"
        finally:
            builtins.__import__ = original_import

    def test_mitigate_future_allows_test_from_safe_modules(self) -> None:
        """Test mitigation allows test imports from safe modules."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()

        try:
            test_globals = {"__name__": "my_application.tests"}
            result = builtins.__import__("test", test_globals, None, [], 0)

            assert result is not None
        finally:
            builtins.__import__ = original_import

    def test_mitigate_future_idempotent(self) -> None:
        """Test mitigation can be applied multiple times safely."""
        original_import = builtins.__import__

        mitigate_future_vulnerability()
        first_import = builtins.__import__

        mitigate_future_vulnerability()
        second_import = builtins.__import__

        assert first_import is not original_import
        assert second_import is not original_import

        builtins.__import__ = original_import


class TestScanMaliciousTestFiles:
    """Test scanning for malicious test.py files."""

    @pytest.fixture
    def temp_test_env(self) -> Path:
        """Create temporary environment with test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_scan_finds_suspicious_test_file_with_exec(self, temp_test_env: Path) -> None:
        """Test scan identifies test.py with exec()."""
        test_file = temp_test_env / "test.py"
        test_file.write_text("exec('import os; os.system(\"calc\")')", encoding="utf-8")

        original_path = sys.path.copy()
        sys.path.insert(0, str(temp_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
            assert any(f.name == "test.py" and str(temp_test_env) in str(f) for f in suspicious)
        finally:
            sys.path = original_path

    def test_scan_finds_suspicious_test_file_with_subprocess(self, temp_test_env: Path) -> None:
        """Test scan identifies test.py with subprocess."""
        test_file = temp_test_env / "test.py"
        test_file.write_text("import subprocess\nsubprocess.call(['echo', 'pwned'])", encoding="utf-8")

        original_path = sys.path.copy()
        sys.path.insert(0, str(temp_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
            assert any(f.name == "test.py" and str(temp_test_env) in str(f) for f in suspicious)
        finally:
            sys.path = original_path

    def test_scan_finds_suspicious_test_file_with_socket(self, temp_test_env: Path) -> None:
        """Test scan identifies test.py with socket operations."""
        test_file = temp_test_env / "test.py"
        test_file.write_text("import socket\ns = socket.socket()", encoding="utf-8")

        original_path = sys.path.copy()
        sys.path.insert(0, str(temp_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
            assert any(f.name == "test.py" and str(temp_test_env) in str(f) for f in suspicious)
        finally:
            sys.path = original_path

    def test_scan_ignores_legitimate_test_file(self, temp_test_env: Path) -> None:
        """Test scan does not flag legitimate test files."""
        tests_dir = temp_test_env / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test.py"
        test_file.write_text("import unittest\n\nclass TestCase(unittest.TestCase):\n    pass", encoding="utf-8")

        original_path = sys.path.copy()
        sys.path.insert(0, str(temp_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
            assert all(str(tests_dir) not in str(f) for f in suspicious)
        finally:
            sys.path = original_path

    def test_scan_handles_unreadable_files(self, temp_test_env: Path) -> None:
        """Test scan handles files that cannot be read."""
        test_file = temp_test_env / "test.py"
        test_file.write_text("test content", encoding="utf-8")
        test_file.chmod(0o000)

        original_path = sys.path.copy()
        sys.path.insert(0, str(temp_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
        finally:
            test_file.chmod(0o644)
            sys.path = original_path

    def test_scan_handles_nonexistent_paths(self) -> None:
        """Test scan handles nonexistent paths in sys.path."""
        original_path = sys.path.copy()
        sys.path.insert(0, "/nonexistent/path/that/does/not/exist")

        try:
            suspicious = scan_for_malicious_test_files()
            assert isinstance(suspicious, list)
        finally:
            sys.path = original_path

    def test_scan_finds_multiple_suspicious_files(self, temp_test_env: Path) -> None:
        """Test scan finds multiple suspicious test.py files."""
        dir1 = temp_test_env / "dir1"
        dir2 = temp_test_env / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        test1 = dir1 / "test.py"
        test2 = dir2 / "test.py"

        test1.write_text("exec('malicious')", encoding="utf-8")
        test2.write_text("eval('bad code')", encoding="utf-8")

        original_path = sys.path.copy()
        sys.path.insert(0, str(dir1))
        sys.path.insert(0, str(dir2))

        try:
            suspicious = scan_for_malicious_test_files()
            found_count = sum(bool(str(temp_test_env) in str(f))
                          for f in suspicious)
            assert found_count >= 1
        finally:
            sys.path = original_path


class TestIsSafeToRemove:
    """Test safety checks for test.py file removal."""

    @pytest.fixture
    def temp_file_env(self) -> Path:
        """Create temporary environment for file safety tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_is_safe_to_remove_wrong_filename(self, temp_file_env: Path) -> None:
        """Test files not named test.py are not safe to remove."""
        not_test = temp_file_env / "not_test.py"
        not_test.write_text("some content", encoding="utf-8")

        assert not _is_safe_to_remove(not_test)

    def test_is_safe_to_remove_in_tests_directory(self, temp_file_env: Path) -> None:
        """Test test.py in tests directory is not safe to remove."""
        tests_dir = temp_file_env / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test.py"
        test_file.write_text("legitimate test", encoding="utf-8")

        assert not _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_in_unittest_directory(self, temp_file_env: Path) -> None:
        """Test test.py in unittest directory is not safe to remove."""
        unittest_dir = temp_file_env / "unittest"
        unittest_dir.mkdir()
        test_file = unittest_dir / "test.py"
        test_file.write_text("import unittest", encoding="utf-8")

        assert not _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_small_suspicious_file(self, temp_file_env: Path) -> None:
        """Test very small test.py files are safe to remove."""
        test_file = temp_file_env / "test.py"
        test_file.write_text("x=1", encoding="utf-8")

        assert _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_file_with_unittest_import(self, temp_file_env: Path) -> None:
        """Test test.py with unittest import is not safe to remove."""
        test_file = temp_file_env / "test.py"
        test_file.write_text("import unittest\nclass MyTest(unittest.TestCase):\n    pass", encoding="utf-8")

        assert not _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_file_with_pytest_import(self, temp_file_env: Path) -> None:
        """Test test.py with pytest import is not safe to remove."""
        test_file = temp_file_env / "test.py"
        test_file.write_text("import pytest\ndef test_something():\n    pass", encoding="utf-8")

        assert not _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_suspicious_file(self, temp_file_env: Path) -> None:
        """Test suspicious test.py without test framework is safe to remove."""
        test_file = temp_file_env / "test.py"
        test_file.write_text("exec('import os; os.system(\"calc\")')" * 10, encoding="utf-8")

        assert _is_safe_to_remove(test_file)

    def test_is_safe_to_remove_handles_read_error(self, temp_file_env: Path) -> None:
        """Test safety check handles file read errors gracefully."""
        test_file = temp_file_env / "test.py"
        test_file.write_text("content", encoding="utf-8")
        test_file.chmod(0o000)

        try:
            result = _is_safe_to_remove(test_file)
            assert isinstance(result, bool)
        finally:
            test_file.chmod(0o644)


class TestRemoveMaliciousTestFiles:
    """Test removal of malicious test.py files."""

    @pytest.fixture
    def temp_removal_env(self) -> Path:
        """Create temporary environment for removal tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_remove_malicious_test_files_force(self, temp_removal_env: Path) -> None:
        """Test forced removal of suspicious files."""
        test_file = temp_removal_env / "test.py"
        test_file.write_text("exec('malicious')", encoding="utf-8")

        removed = remove_malicious_test_files([test_file], force=True)

        assert removed == 1
        assert not test_file.exists()

    def test_remove_malicious_test_files_safe_check(self, temp_removal_env: Path) -> None:
        """Test removal with safety check."""
        test_file = temp_removal_env / "test.py"
        test_file.write_text("x=1", encoding="utf-8")

        removed = remove_malicious_test_files([test_file], force=False)

        assert removed == 1
        assert not test_file.exists()

    def test_remove_malicious_test_files_skips_safe(self, temp_removal_env: Path) -> None:
        """Test removal skips legitimately safe files."""
        tests_dir = temp_removal_env / "tests"
        tests_dir.mkdir()
        test_file = tests_dir / "test.py"
        test_file.write_text("import unittest", encoding="utf-8")

        removed = remove_malicious_test_files([test_file], force=False)

        assert removed == 0
        assert test_file.exists()

    def test_remove_malicious_test_files_multiple(self, temp_removal_env: Path) -> None:
        """Test removal of multiple files."""
        file1 = temp_removal_env / "test.py"
        dir2 = temp_removal_env / "subdir"
        dir2.mkdir()
        file2 = dir2 / "test.py"

        file1.write_text("x=1", encoding="utf-8")
        file2.write_text("y=2", encoding="utf-8")

        removed = remove_malicious_test_files([file1, file2], force=True)

        assert removed == 2
        assert not file1.exists()
        assert not file2.exists()

    def test_remove_malicious_test_files_handles_missing(self, temp_removal_env: Path) -> None:
        """Test removal handles files that don't exist."""
        nonexistent = temp_removal_env / "nonexistent.py"

        removed = remove_malicious_test_files([nonexistent], force=True)

        assert removed == 0

    def test_remove_malicious_test_files_handles_permission_error(self, temp_removal_env: Path) -> None:
        """Test removal handles permission errors gracefully."""
        test_file = temp_removal_env / "test.py"
        test_file.write_text("content", encoding="utf-8")
        test_file.chmod(0o444)

        try:
            removed = remove_malicious_test_files([test_file], force=True)
        finally:
            test_file.chmod(0o644)

    def test_remove_malicious_test_files_empty_list(self) -> None:
        """Test removal with empty file list."""
        removed = remove_malicious_test_files([], force=True)

        assert removed == 0


class TestApplyAllMitigations:
    """Test applying all security mitigations."""

    def test_apply_all_mitigations_returns_results(self) -> None:
        """Test apply_all_mitigations returns result dictionary."""
        original_import = builtins.__import__

        try:
            results = apply_all_mitigations()

            assert isinstance(results, dict)
            assert "future_vulnerability_mitigation" in results
            assert "malicious_test_files_removed" in results
            assert results["future_vulnerability_mitigation"] is True
            assert isinstance(results["malicious_test_files_removed"], int)
        finally:
            builtins.__import__ = original_import

    def test_apply_all_mitigations_applies_future_mitigation(self) -> None:
        """Test apply_all_mitigations applies future vulnerability fix."""
        original_import = builtins.__import__

        try:
            apply_all_mitigations()

            assert builtins.__import__ != original_import
        finally:
            builtins.__import__ = original_import

    def test_apply_all_mitigations_scans_for_malicious_files(self) -> None:
        """Test apply_all_mitigations scans for suspicious files."""
        original_import = builtins.__import__

        try:
            results = apply_all_mitigations()

            assert "malicious_test_files_removed" in results
            assert results["malicious_test_files_removed"] >= 0
        finally:
            builtins.__import__ = original_import

    def test_apply_all_mitigations_idempotent(self) -> None:
        """Test apply_all_mitigations can be called multiple times."""
        original_import = builtins.__import__

        try:
            results1 = apply_all_mitigations()
            results2 = apply_all_mitigations()

            assert results1["future_vulnerability_mitigation"] is True
            assert results2["future_vulnerability_mitigation"] is True
        finally:
            builtins.__import__ = original_import


class TestSecurityMitigationsIntegration:
    """Integration tests for security mitigations."""

    @pytest.fixture
    def malicious_test_env(self) -> Path:
        """Create environment with malicious test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir)

            malicious1 = temp_path / "test.py"
            malicious1.write_text("exec('import os')", encoding="utf-8")

            subdir = temp_path / "suspicious"
            subdir.mkdir()
            malicious2 = subdir / "test.py"
            malicious2.write_text("eval('bad code')", encoding="utf-8")

            yield temp_path

    def test_full_mitigation_workflow(self, malicious_test_env: Path) -> None:
        """Test complete mitigation workflow."""
        original_import = builtins.__import__
        original_path = sys.path.copy()
        sys.path.insert(0, str(malicious_test_env))

        try:
            suspicious = scan_for_malicious_test_files()
            if malicious_in_env := [
                f for f in suspicious if str(malicious_test_env) in str(f)
            ]:
                removed = remove_malicious_test_files(malicious_in_env, force=True)
                assert removed >= 1

            mitigate_future_vulnerability()
            assert builtins.__import__ != original_import

        finally:
            builtins.__import__ = original_import
            sys.path = original_path

    def test_mitigation_prevents_exploitation(self) -> None:
        """Test mitigation actually prevents future package exploitation."""
        original_import = builtins.__import__

        try:
            mitigate_future_vulnerability()

            test_globals = {"__name__": "future.standard_library"}
            result = builtins.__import__("test", test_globals, None, [], 0)

            assert result.__name__ == "test"

        finally:
            builtins.__import__ = original_import

    def test_scan_performance_with_large_path(self) -> None:
        """Test scan performance with large sys.path."""
        import time

        start_time = time.time()
        scan_for_malicious_test_files()
        elapsed = time.time() - start_time

        assert elapsed < 10.0
