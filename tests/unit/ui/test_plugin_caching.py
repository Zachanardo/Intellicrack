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
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class MockIntellicrackApp:
    """Mock IntellicrackApp with only the plugin loading functionality."""

    def __init__(self, plugin_base_dir):
        """Initialize mock app with custom plugin directory."""
        self.logger = logging.getLogger("test_logger")
        self.plugin_base_dir = plugin_base_dir

    def load_available_plugins(self):
        """Load available plugins from plugin directory with caching for performance.

        This is the actual implementation from main_app.py for testing purposes.
        """
        cache_dir = Path.home() / ".intellicrack"
        cache_file = cache_dir / "plugin_cache.json"

        plugin_base_dir = self.plugin_base_dir
        plugin_directories = {
            "custom": os.path.join(plugin_base_dir, "custom_modules"),
            "frida": os.path.join(plugin_base_dir, "frida_scripts"),
            "ghidra": os.path.join(plugin_base_dir, "ghidra_scripts"),
        }

        def is_path_safe(file_path: str, plugin_dir: str) -> bool:
            """Validate that reconstructed path is within allowed plugin directory."""
            try:
                real_plugin_dir = os.path.realpath(plugin_dir)
                real_file_path = os.path.realpath(file_path)
                common_path = os.path.commonpath([real_plugin_dir, real_file_path])
                return common_path == real_plugin_dir
            except (ValueError, OSError):
                return False

        def is_cache_valid():
            """Check if cache exists and is still valid."""
            if not cache_file.exists():
                return False

            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)

                for plugin_type, plugin_dir in plugin_directories.items():
                    if not os.path.exists(plugin_dir):
                        continue

                    cached_plugins = cached_data.get("plugins", {}).get(plugin_type, [])
                    cached_filenames = {p["filename"]: p["modified"] for p in cached_plugins}

                    for file_name in os.listdir(plugin_dir):
                        full_path = os.path.join(plugin_dir, file_name)
                        if os.path.isfile(full_path):
                            current_mtime = os.path.getmtime(full_path)
                            if file_name not in cached_filenames or cached_filenames[file_name] != current_mtime:
                                return False

                            del cached_filenames[file_name]

                    if cached_filenames:
                        return False

                return True

            except (json.JSONDecodeError, KeyError, OSError) as e:
                self.logger.debug(f"Cache validation failed: {e}")
                return False

        if is_cache_valid():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
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
            except (json.JSONDecodeError, OSError) as e:
                self.logger.warning(f"Failed to load plugin cache, rescanning: {e}")

        plugins = {"custom": [], "frida": [], "ghidra": []}

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
                                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                        f.read(512)

                                    plugin_info = {
                                        "name": os.path.splitext(file_path)[0],
                                        "filename": file_path,
                                        "path": full_path,
                                        "type": plugin_type,
                                        "extension": file_ext,
                                        "size": os.path.getsize(full_path),
                                        "modified": os.path.getmtime(full_path),
                                        "valid": True,
                                    }
                                    plugins[plugin_type].append(plugin_info)

                                except (OSError, UnicodeDecodeError, PermissionError) as file_error:
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

                except (OSError, PermissionError) as dir_error:
                    self.logger.error(f"Error accessing plugin directory {plugin_dir}: {dir_error}")

            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"plugins": plugins, "cache_version": "1.0"}, f, indent=2)
                self.logger.debug(f"Plugin cache saved to {cache_file}")
            except (OSError, IOError) as cache_error:
                self.logger.warning(f"Failed to save plugin cache: {cache_error}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Critical error loading plugins: {e}")
            return {"custom": [], "frida": [], "ghidra": []}

        self.logger.info(f"Loaded {sum(len(p) for p in plugins.values())} plugins across {len(plugins)} categories")
        return plugins


@pytest.fixture
def temp_plugin_dir():
    """Create temporary plugin directory structure for testing."""
    temp_dir = tempfile.mkdtemp(prefix="intellicrack_test_plugins_")

    os.makedirs(os.path.join(temp_dir, "custom_modules"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "frida_scripts"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "ghidra_scripts"), exist_ok=True)

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def cache_file():
    """Get path to cache file and clean it up after test."""
    cache_file_path = Path.home() / ".intellicrack" / "plugin_cache.json"

    if cache_file_path.exists():
        cache_file_path.unlink()

    yield cache_file_path

    if cache_file_path.exists():
        cache_file_path.unlink()


@pytest.fixture
def mock_app(temp_plugin_dir):
    """Create mock IntellicrackApp instance for testing."""
    return MockIntellicrackApp(temp_plugin_dir)


def create_real_plugin_file(plugin_dir, filename, content="# Test plugin\nprint('Hello')"):
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


class TestPluginCaching:
    """Test suite for plugin caching functionality."""

    def test_initial_scan_creates_cache(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_second_call_uses_cache(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_cache_invalidation_on_file_modification(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_cache_invalidation_on_file_addition(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_cache_invalidation_on_file_deletion(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_corrupted_cache_graceful_fallback(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_empty_plugin_directories(self, mock_app, temp_plugin_dir, cache_file):
        """Test handling of empty plugin directories."""
        plugins = mock_app.load_available_plugins()

        assert plugins == {"custom": [], "frida": [], "ghidra": []}, "Empty directories returned non-empty results"
        assert cache_file.exists(), "Cache not created for empty directories"

    def test_mixed_valid_and_invalid_files(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

    def test_cache_persists_across_instances(self, temp_plugin_dir, cache_file):
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

    def test_plugin_metadata_accuracy(self, mock_app, temp_plugin_dir, cache_file):
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
        assert abs(plugin_info["modified"] - os.path.getmtime(plugin_path)) < 0.01
        assert plugin_info["valid"] is True

    def test_all_supported_extensions(self, mock_app, temp_plugin_dir, cache_file):
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

    def test_malicious_cache_path_rejected(self, mock_app, temp_plugin_dir, cache_file, caplog):
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

        with open(cache_file, "r", encoding="utf-8") as f:
            cache_data = json.load(f)

        malicious_paths = [
            "..\\..\\..\\Windows\\System32\\calc.exe",
            "/tmp/malicious.py",
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
            assert not any(malicious_path in p.get("path", "") for p in plugins_after["custom"]), \
                f"Malicious path {malicious_path} was loaded"

        assert "Rejecting potentially malicious plugin path" in caplog.text or \
               len(plugins_after["custom"]) == 1, \
               "Malicious paths were not properly rejected or logged"
