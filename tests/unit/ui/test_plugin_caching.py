"""Unit tests for plugin caching functionality in main_app.py.

Tests verify that the plugin loading cache mechanism correctly handles:
- Cache creation and validation
- Cache invalidation on file modifications
- Cache invalidation on file additions/deletions
- Graceful fallback on corrupted cache
- Performance improvement from caching

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
import shutil
import tempfile
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


class MockIntellicrackApp:
    """Mock IntellicrackApp with only the plugin loading functionality."""

    def __init__(self, plugin_base_dir: str) -> None:
        """Initialize mock app with custom plugin directory."""
        self.logger = logging.getLogger("test_logger")
        self.plugin_base_dir = plugin_base_dir

    def _load_cache_data(self, cache_file: Path) -> dict[str, Any] | None:
        """Load and parse cache data from file.

        Args:
            cache_file: Path to cache file

        Returns:
            dict: Parsed cache data, or None if loading fails

        """
        import json

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.debug(f"Failed to load cache data: {e}")
            return None

    def _check_file_modifications(
        self, plugin_dir: str, cached_filenames: dict[str, float]
    ) -> tuple[bool, dict[str, float]]:
        """Check if files in directory have been modified compared to cache.

        Args:
            plugin_dir: Path to plugin directory
            cached_filenames: Dict mapping filenames to cached modification times

        Returns:
            tuple: (is_valid, remaining_cached_files) where is_valid indicates if
                   all files match cache, and remaining_cached_files contains files
                   that were in cache but not found in directory

        """
        remaining = dict(cached_filenames)

        try:
            for file_name in os.listdir(plugin_dir):
                full_path = os.path.join(plugin_dir, file_name)
                if os.path.isfile(full_path):
                    current_mtime = Path(full_path).stat().st_mtime
                    if file_name not in remaining or remaining[file_name] != current_mtime:
                        return False, {}
                    del remaining[file_name]
        except OSError as e:
            self.logger.debug(f"Error checking file modifications: {e}")
            return False, {}

        return True, remaining

    def _validate_plugin_directory_cache(
        self, plugin_type: str, plugin_dir: str, cached_data: dict[str, Any]
    ) -> bool:
        """Validate cache for a specific plugin directory.

        Args:
            plugin_type: Type of plugin (custom, frida, ghidra)
            plugin_dir: Path to plugin directory
            cached_data: Complete cached data dictionary

        Returns:
            bool: True if cache is valid for this directory, False otherwise

        """
        cached_plugins = cached_data.get("plugins", {}).get(plugin_type, [])

        if not os.path.exists(plugin_dir):
            return not cached_plugins

        cached_filenames = {p["filename"]: p["modified"] for p in cached_plugins}
        is_valid, remaining = self._check_file_modifications(plugin_dir, cached_filenames)

        return len(remaining) == 0 if is_valid else False

    def load_available_plugins(self) -> dict[str, list[dict[str, Any]]]:
        """Load available plugins from plugin directory with caching for performance.

        This is the actual implementation from main_app.py for testing purposes.
        """
        from filelock import FileLock

        cache_dir = Path.home() / ".intellicrack"
        cache_file = cache_dir / "plugin_cache.json"
        cache_lock_file = cache_dir / "plugin_cache.json.lock"

        plugin_base_dir = self.plugin_base_dir
        plugin_directories = {
            "custom": os.path.join(plugin_base_dir, "custom_modules"),
            "frida": os.path.join(plugin_base_dir, "frida_scripts"),
            "ghidra": os.path.join(plugin_base_dir, "ghidra_scripts"),
        }

        def is_path_safe(file_path: str, plugin_dir_path: str) -> bool:
            """Validate that reconstructed path is within allowed plugin directory."""
            try:
                real_plugin_dir = os.path.realpath(plugin_dir_path)
                real_file_path = os.path.realpath(file_path)
                common_path = os.path.commonpath([real_plugin_dir, real_file_path])
                return common_path == real_plugin_dir
            except (ValueError, OSError):
                return False

        def is_cache_valid() -> tuple[bool, dict[str, Any] | None]:
            """Check if cache exists and is still valid.

            Returns:
                tuple: (is_valid, cached_data) where is_valid is True if cache is valid,
                       and cached_data contains the loaded cache or None if invalid

            """
            cached_data = self._load_cache_data(cache_file)
            if cached_data is None:
                return False, None

            for plugin_type, plugin_dir in plugin_directories.items():
                if not self._validate_plugin_directory_cache(plugin_type, plugin_dir, cached_data):
                    return False, None

            return True, cached_data

        lock = FileLock(str(cache_lock_file), timeout=10)

        cache_is_valid, cached_data = is_cache_valid()
        if cache_is_valid:
            try:
                cached_plugins = cached_data.get("plugins", {"custom": [], "frida": [], "ghidra": []})

                plugins = {"custom": [], "frida": [], "ghidra": []}
                for plugin_type, plugin_list in cached_plugins.items():
                    if plugin_type not in plugin_directories:
                        continue

                    plugin_dir = plugin_directories[plugin_type]
                    for plugin_info in plugin_list:
                        filename = plugin_info.get("filename")
                        if not filename:
                            continue

                        reconstructed_path = os.path.join(plugin_dir, filename)

                        if not is_path_safe(reconstructed_path, plugin_dir):
                            self.logger.warning(f"Rejecting potentially malicious plugin path: {filename}")
                            continue

                        if not os.path.exists(reconstructed_path):
                            continue

                        plugin_info_with_path = plugin_info.copy()
                        plugin_info_with_path["path"] = reconstructed_path
                        plugins[plugin_type].append(plugin_info_with_path)

                self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins from cache")
                return plugins
            except (KeyError, OSError) as e:
                self.logger.warning(f"Failed to load plugin cache, rescanning: {e}")

        plugins = {"custom": [], "frida": [], "ghidra": []}

        BINARY_EXTENSIONS = {".pyd", ".dll", ".jar"}

        try:
            for plugin_type, plugin_dir in plugin_directories.items():
                try:
                    if not os.path.exists(plugin_dir):
                        self.logger.info(f"Plugin directory not found, creating: {plugin_dir}")
                        os.makedirs(plugin_dir, exist_ok=True)
                        continue

                    plugin_extensions = {"custom": [".py", ".pyd", ".dll"], "frida": [".js", ".ts"], "ghidra": [".py", ".java", ".jar"]}

                    for file_path in os.listdir(plugin_dir):
                        full_path = os.path.join(plugin_dir, file_path)
                        if os.path.isfile(full_path):
                            file_ext = os.path.splitext(file_path)[1].lower()
                            if file_ext in plugin_extensions.get(plugin_type, []):
                                try:
                                    if file_ext in BINARY_EXTENSIONS:
                                        with open(full_path, "rb") as f:
                                            f.read(512)
                                    else:
                                        with open(full_path, encoding="utf-8") as f:
                                            f.read(512)

                                    plugin_info = {
                                        "name": os.path.splitext(file_path)[0],
                                        "filename": file_path,
                                        "path": full_path,
                                        "type": plugin_type,
                                        "extension": file_ext,
                                        "size": os.path.getsize(full_path),
                                        "modified": Path(full_path).stat().st_mtime,
                                        "valid": True,
                                    }
                                    plugins[plugin_type].append(plugin_info)

                                except (OSError, UnicodeDecodeError) as file_error:
                                    self.logger.warning(f"Failed to validate plugin {file_path}: {file_error}")
                                    plugins[plugin_type].append(
                                        {
                                            "name": os.path.splitext(file_path)[0],
                                            "filename": file_path,
                                            "path": full_path,
                                            "type": plugin_type,
                                            "valid": False,
                                            "error": str(file_error),
                                        }
                                    )

                except OSError as dir_error:
                    self.logger.error(f"Error accessing plugin directory {plugin_dir}: {dir_error}")

            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                with lock, open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"plugins": plugins, "cache_version": "1.0"}, f, indent=2)
                self.logger.debug(f"Plugin cache saved to {cache_file}")
            except OSError as cache_error:
                self.logger.warning(f"Failed to save plugin cache: {cache_error}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Critical error loading plugins: {e}")
            return {"custom": [], "frida": [], "ghidra": []}

        self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins across {len(plugins)} categories")
        return plugins


@pytest.fixture
def temp_plugin_dir() -> Generator[str, None, None]:
    """Create temporary plugin directory structure for testing."""
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_plugins_")

    os.makedirs(os.path.join(temp_dir, "custom_modules"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "frida_scripts"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "ghidra_scripts"), exist_ok=True)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def cache_file() -> Generator[Path, None, None]:
    """Get path to cache file and clean it up after test."""
    cache_file_path = Path.home() / ".intellicrack" / "plugin_cache.json"

    if cache_file_path.exists():
        cache_file_path.unlink()

    yield cache_file_path

    if cache_file_path.exists():
        cache_file_path.unlink()


@pytest.fixture
def mock_app(temp_plugin_dir: str) -> MockIntellicrackApp:
    """Create mock IntellicrackApp instance for testing."""
    return MockIntellicrackApp(temp_plugin_dir)


def create_real_plugin_file(
    plugin_dir: str, filename: str, content: str = "# Test plugin\nprint('Hello')"
) -> str:
    """Create a real plugin file with actual content.

    Args:
        plugin_dir: Directory to create plugin in
        filename: Name of plugin file
        content: Content to write to file

    Returns:
        str: Full path to created file

    """
    file_path = os.path.join(plugin_dir, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    return file_path


def load_plugins_worker(plugin_base_dir: str) -> dict[str, Any]:
    """Worker function to load plugins in separate process for concurrency testing."""
    try:
        app = MockIntellicrackApp(plugin_base_dir)
        plugins = app.load_available_plugins()
        return {
            "success": True,
            "plugin_count": sum(len(p) for p in plugins.values()),
            "has_custom": len(plugins.get("custom", [])),
            "has_frida": len(plugins.get("frida", [])),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


class TestPluginCaching:
    """Test suite for plugin caching functionality."""

    def test_initial_scan_creates_cache(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that initial plugin scan creates cache file."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "test_plugin.py",
            "# Custom plugin\ndef analyze_binary():\n    pass"
        )
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "hook_script.js",
            "// Frida hook\nInterceptor.attach(ptr('0x1234'), {});"
        )

        caplog.set_level(logging.INFO)

        plugins = mock_app.load_available_plugins()

        assert cache_file.exists(), "Cache file was not created after initial scan"
        assert len(plugins["custom"]) == 1, "Custom plugin not detected"
        assert len(plugins["frida"]) == 1, "Frida script not detected"
        assert plugins["custom"][0]["name"] == "test_plugin"
        assert plugins["frida"][0]["name"] == "hook_script"

        assert "Loaded 2 plugins across 3 categories" in caplog.text

    def test_second_call_uses_cache(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that second call uses cache instead of rescanning filesystem."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "cached_plugin.py",
            "# Cached plugin\ndef main(): pass"
        )

        caplog.set_level(logging.INFO)
        caplog.clear()

        first_plugins = mock_app.load_available_plugins()

        caplog.clear()

        second_plugins = mock_app.load_available_plugins()

        assert "Loaded 1 plugins from cache" in caplog.text, "Second call did not use cache"
        assert first_plugins == second_plugins, "Cache returned different data than initial scan"
        assert cache_file.exists(), "Cache file was deleted"

    def test_cache_invalidation_on_file_modification(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that modifying a plugin file invalidates cache."""
        plugin_path = create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "modified_plugin.py",
            "# Original content"
        )

        mock_app.load_available_plugins()

        assert cache_file.exists()

        time.sleep(0.1)

        with open(plugin_path, "a", encoding="utf-8") as f:
            f.write("\n# Modified content")

        caplog.set_level(logging.INFO)
        caplog.clear()

        plugins = mock_app.load_available_plugins()

        assert "Loaded 1 plugins from cache" not in caplog.text, "Cache was used despite file modification"
        assert len(plugins["custom"]) == 1
        assert plugins["custom"][0]["size"] > 20, "Modified file size not detected"

    def test_cache_invalidation_on_file_addition(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that adding a new plugin file invalidates cache."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "existing_script.js",
            "// Existing script"
        )

        first_plugins = mock_app.load_available_plugins()
        assert len(first_plugins["frida"]) == 1

        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "new_script.js",
            "// New script added"
        )

        caplog.set_level(logging.INFO)
        caplog.clear()

        second_plugins = mock_app.load_available_plugins()

        assert "Loaded 1 plugins from cache" not in caplog.text, "Cache was used despite new file"
        assert len(second_plugins["frida"]) == 2, "New plugin not detected"

    def test_cache_invalidation_on_file_deletion(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that deleting a plugin file invalidates cache."""
        plugin1 = create_real_plugin_file(
            os.path.join(temp_plugin_dir, "ghidra_scripts"),
            "script1.py",
            "# Script 1"
        )
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "ghidra_scripts"),
            "script2.py",
            "# Script 2"
        )

        first_plugins = mock_app.load_available_plugins()
        assert len(first_plugins["ghidra"]) == 2

        os.remove(plugin1)

        caplog.set_level(logging.INFO)
        caplog.clear()

        second_plugins = mock_app.load_available_plugins()

        assert "Loaded 2 plugins from cache" not in caplog.text, "Cache was used despite file deletion"
        assert len(second_plugins["ghidra"]) == 1, "Deleted plugin still appears in results"

    def test_corrupted_cache_graceful_fallback(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that corrupted cache triggers graceful rescan."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "valid_plugin.py",
            "# Valid plugin"
        )

        mock_app.load_available_plugins()

        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write("{ CORRUPTED JSON DATA ][")

        caplog.set_level(logging.DEBUG)
        caplog.clear()

        plugins = mock_app.load_available_plugins()

        assert "Cache validation failed" in caplog.text or len(plugins["custom"]) == 1, "Failed to handle corrupted cache"
        assert len(plugins["custom"]) == 1, "Failed to recover from corrupted cache"
        assert cache_file.exists(), "Cache was not recreated after corruption"

    def test_empty_plugin_directories(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path
    ) -> None:
        """Test handling of empty plugin directories."""
        plugins = mock_app.load_available_plugins()

        assert plugins == {"custom": [], "frida": [], "ghidra": []}, "Empty directories returned non-empty results"
        assert cache_file.exists(), "Cache not created for empty directories"

    def test_mixed_valid_and_invalid_files(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test handling of both valid and invalid plugin files."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "valid.py",
            "# Valid Python plugin"
        )

        invalid_path = os.path.join(temp_plugin_dir, "custom_modules", "not_a_plugin.txt")
        with open(invalid_path, "w") as f:
            f.write("This is not a plugin")

        plugins = mock_app.load_available_plugins()

        assert len(plugins["custom"]) == 1, "Invalid file was included in results"
        assert plugins["custom"][0]["name"] == "valid", "Wrong plugin detected"

    def test_cache_persists_across_instances(self, temp_plugin_dir: str, cache_file: Path) -> None:
        """Test that cache persists and works across different app instances."""
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "persistent.js",
            "// Persistent script"
        )

        app1 = MockIntellicrackApp(temp_plugin_dir)
        plugins1 = app1.load_available_plugins()

        app2 = MockIntellicrackApp(temp_plugin_dir)
        plugins2 = app2.load_available_plugins()

        assert plugins1 == plugins2, "Different instances returned different cached data"
        assert len(plugins2["frida"]) == 1

    def test_plugin_metadata_accuracy(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path
    ) -> None:
        """Test that cached plugin metadata matches actual file properties."""
        plugin_content = "# Test plugin with some content\ndef analyze(): pass\n"
        plugin_path = create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "metadata_test.py",
            plugin_content
        )

        plugins = mock_app.load_available_plugins()

        plugin_info = plugins["custom"][0]
        assert plugin_info["name"] == "metadata_test"
        assert plugin_info["path"] == plugin_path
        assert plugin_info["type"] == "custom"
        assert plugin_info["extension"] == ".py"
        assert plugin_info["size"] == os.path.getsize(plugin_path)
        assert abs(plugin_info["modified"] - Path(plugin_path).stat().st_mtime) < 0.01
        assert plugin_info["valid"] is True

    def test_all_supported_extensions(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path
    ) -> None:
        """Test that all documented plugin extensions are detected."""
        extensions_to_test = {
            "custom": [".py"],
            "frida": [".js", ".ts"],
            "ghidra": [".py", ".java"],
        }

        for plugin_type, extensions in extensions_to_test.items():
            plugin_dir = os.path.join(temp_plugin_dir, f"{plugin_type}_{'modules' if plugin_type == 'custom' else 'scripts'}")
            for ext in extensions:
                create_real_plugin_file(
                    plugin_dir,
                    f"test_plugin{ext}",
                    "# Test content"
                )

        plugins = mock_app.load_available_plugins()

        assert len(plugins["custom"]) >= 1
        assert len(plugins["frida"]) >= 2
        assert len(plugins["ghidra"]) >= 2

    def test_malicious_cache_path_rejected(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that malicious paths injected into cache are rejected.

        Security test for path injection vulnerability (CRITICAL).
        Verifies that if a malicious actor modifies the cache file to inject
        arbitrary file paths outside plugin directories, they are rejected.
        """
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "legitimate_plugin.py",
            "# Legitimate plugin"
        )

        plugins = mock_app.load_available_plugins()
        assert len(plugins["custom"]) == 1
        assert cache_file.exists()

        with open(cache_file, encoding="utf-8") as f:
            cache_data = json.load(f)

        malicious_paths = [
            "..\\..\\..\\Windows\\System32\\calc.exe",
            "/tmp/malicious.py",  # noqa: S108 - Intentional test path for security validation
            "C:\\evil\\malware.py",
            "../../../etc/passwd",
        ]

        for malicious_path in malicious_paths:
            cache_data["plugins"]["custom"].append({
                "name": "malicious",
                "filename": malicious_path,
                "type": "custom",
                "extension": ".py",
                "size": 1024,
                "modified": time.time(),
                "valid": True,
            })

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f)

        caplog.set_level(logging.WARNING)
        caplog.clear()

        plugins_after = mock_app.load_available_plugins()

        assert len(plugins_after["custom"]) == 1, "Malicious plugins were loaded from cache"
        assert plugins_after["custom"][0]["name"] == "legitimate_plugin", "Wrong plugin loaded"

        for malicious_path in malicious_paths:
            assert all(
                malicious_path not in p.get("path", "")
                for p in plugins_after["custom"]
            ), f"Malicious path {malicious_path} was loaded"

        assert "Rejecting potentially malicious plugin path" in caplog.text or \
                   len(plugins_after["custom"]) == 1, \
                   "Malicious paths were not properly rejected or logged"

    def test_concurrent_cache_access(self, temp_plugin_dir: str, cache_file: Path) -> None:
        """Test that concurrent cache access doesn't corrupt cache file.

        Security test for race condition (HIGH).
        Verifies that multiple Intellicrack instances can load plugins
        simultaneously without corrupting the cache file or causing crashes.
        """
        from concurrent.futures import ProcessPoolExecutor, as_completed

        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "concurrent_test.py",
            "# Concurrent access test plugin"
        )
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "concurrent_test.js",
            "// Concurrent access test script"
        )

        num_concurrent_processes = 5
        results = []

        with ProcessPoolExecutor(max_workers=num_concurrent_processes) as executor:
            futures = [
                executor.submit(load_plugins_worker, temp_plugin_dir)
                for _ in range(num_concurrent_processes)
            ]

            for future in as_completed(futures):
                result = future.result(timeout=30)
                results.append(result)

        assert len(results) == num_concurrent_processes, \
            f"Expected {num_concurrent_processes} results, got {len(results)}"

        for i, result in enumerate(results):
            assert result["success"], \
                f"Process {i} failed: {result.get('error', 'Unknown error')}"
            assert result["plugin_count"] == 2, \
                f"Process {i} loaded {result['plugin_count']} plugins instead of 2"
            assert result["has_custom"] == 1, \
                f"Process {i} loaded {result['has_custom']} custom plugins instead of 1"
            assert result["has_frida"] == 1, \
                f"Process {i} loaded {result['has_frida']} frida plugins instead of 1"

        assert cache_file.exists(), "Cache file doesn't exist after concurrent access"

        try:
            with open(cache_file, encoding="utf-8") as f:
                cache_data = json.load(f)
                assert "plugins" in cache_data, "Cache file missing 'plugins' key"
                assert isinstance(cache_data["plugins"], dict), \
                    "Cache plugins is not a dictionary"
        except json.JSONDecodeError:
            pytest.fail("Cache file corrupted after concurrent access")

    def test_cache_invalidation_on_directory_deletion(
        self, mock_app: MockIntellicrackApp, temp_plugin_dir: str, cache_file: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that cache is invalidated when entire plugin directory is deleted.

        Security test for stale cache entries (HIGH).
        Verifies that if a plugin directory is deleted after cache creation,
        the cache is invalidated and rescanning occurs without errors.
        """
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "custom_modules"),
            "dir_test_plugin.py",
            "# Plugin in directory that will be deleted"
        )
        create_real_plugin_file(
            os.path.join(temp_plugin_dir, "frida_scripts"),
            "dir_test_script.js",
            "// Script in directory that will be deleted"
        )

        first_plugins = mock_app.load_available_plugins()
        assert len(first_plugins["custom"]) == 1, "Should have 1 custom plugin"
        assert len(first_plugins["frida"]) == 1, "Should have 1 frida script"
        assert cache_file.exists(), "Cache should exist after first load"

        shutil.rmtree(os.path.join(temp_plugin_dir, "custom_modules"))

        caplog.set_level(logging.INFO)
        caplog.clear()

        second_plugins = mock_app.load_available_plugins()

        assert "Loaded 2 plugins from cache" not in caplog.text, \
            "Cache should have been invalidated due to deleted directory"
        assert len(second_plugins["custom"]) == 0, \
            "Should have 0 custom plugins after directory deletion"
        assert len(second_plugins["frida"]) == 1, \
            "Should still have 1 frida script (directory not deleted)"

        os.makedirs(os.path.join(temp_plugin_dir, "custom_modules"), exist_ok=True)
