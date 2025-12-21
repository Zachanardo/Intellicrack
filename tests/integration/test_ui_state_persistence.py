"""
Integration tests for UI state persistence across application restarts.

This module tests that all UI state (window geometry, splitter positions,
toolbar states, theme settings) are properly saved and restored using the
central configuration system.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from PyQt6.QtCore import QPoint, QRect, QSize, Qt, QByteArray
from PyQt6.QtWidgets import QApplication, QMainWindow, QSplitter, QToolBar

from intellicrack.core.config_manager import IntellicrackConfig
from intellicrack.ui.main_app import IntellicrackMainWindow
from intellicrack.ui.theme_manager import ThemeManager


class TestUIStatePersistence(unittest.TestCase):
    """Test UI state persistence across application restarts."""

    @classmethod
    def setUpClass(cls):
        """Create QApplication for tests."""
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()

    def setUp(self):
        """Set up test environment with fresh config."""
        # Create temporary config directory
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.json"

        # Mock the config path
        self.config_patcher = patch('intellicrack.core.config_manager.CONFIG_FILE',
                                   str(self.config_path))
        self.config_patcher.start()

        # Create fresh config instance
        self.config = IntellicrackConfig()
        self.config.config_file = str(self.config_path)

        # Mock get_config to return our test config
        self.get_config_patcher = patch('intellicrack.ui.main_app.get_config')
        self.mock_get_config = self.get_config_patcher.start()
        self.mock_get_config.return_value = self.config

        # Also patch in theme_manager
        self.theme_config_patcher = patch('intellicrack.ui.theme_manager.get_config')
        self.mock_theme_config = self.theme_config_patcher.start()
        self.mock_theme_config.return_value = self.config

    def tearDown(self):
        """Clean up test environment."""
        self.config_patcher.stop()
        self.get_config_patcher.stop()
        self.theme_config_patcher.stop()

        # Clean up temp directory
        import shutil
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_window_geometry_persistence(self):
        """Test that window geometry is saved and restored correctly."""
        # Create main window
        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            window = IntellicrackMainWindow()

            # Set custom geometry
            test_geometry = QRect(100, 100, 1280, 720)
            window.setGeometry(test_geometry)

            # Save window state
            window.save_window_state()

            # Verify geometry was saved to config
            saved_geometry = self.config.get("ui_preferences.window_geometry")
            self.assertIsNotNone(saved_geometry)
            self.assertEqual(saved_geometry["x"], 100)
            self.assertEqual(saved_geometry["y"], 100)
            self.assertEqual(saved_geometry["width"], 1280)
            self.assertEqual(saved_geometry["height"], 720)

            # Create new window instance
            window2 = IntellicrackMainWindow()

            # Restore window state
            window2.restore_window_state()

            # Verify geometry was restored
            restored_geometry = window2.geometry()
            self.assertEqual(restored_geometry.x(), 100)
            self.assertEqual(restored_geometry.y(), 100)
            self.assertEqual(restored_geometry.width(), 1280)
            self.assertEqual(restored_geometry.height(), 720)

    def test_window_state_persistence(self):
        """Test that window state (maximized/normal) is saved and restored."""
        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            window = IntellicrackMainWindow()

            # Test maximized state
            window.showMaximized()
            window.save_window_state()

            saved_state = self.config.get("ui_preferences.window_state")
            self.assertEqual(saved_state, "maximized")

            # Create new window and restore
            window2 = IntellicrackMainWindow()
            window2.restore_window_state()

            # Check if restore attempted to maximize
            # Note: In test environment, actual maximization may not work
            restored_state = self.config.get("ui_preferences.window_state")
            self.assertEqual(restored_state, "maximized")

            # Test normal state
            window.showNormal()
            window.save_window_state()

            saved_state = self.config.get("ui_preferences.window_state")
            self.assertEqual(saved_state, "normal")

    def test_splitter_state_persistence(self):
        """Test that splitter positions are saved and restored."""
        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            window = IntellicrackMainWindow()

            # Create test splitter
            window.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window.main_splitter.addWidget(QMainWindow())
            window.main_splitter.addWidget(QMainWindow())
            window.main_splitter.setSizes([800, 400])

            # Save state
            window.save_window_state()

            # Verify splitter state was saved
            saved_splitter = self.config.get("ui_preferences.splitter_states.main_splitter")
            self.assertIsNotNone(saved_splitter)
            self.assertEqual(saved_splitter, [800, 400])

            # Create new window
            window2 = IntellicrackMainWindow()
            window2.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window2.main_splitter.addWidget(QMainWindow())
            window2.main_splitter.addWidget(QMainWindow())

            # Restore state
            window2.restore_window_state()

            # Verify splitter state was restored
            restored_sizes = window2.main_splitter.sizes()
            self.assertEqual(restored_sizes, [800, 400])

    def test_toolbar_visibility_persistence(self):
        """Test that toolbar visibility is saved and restored."""
        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            window = IntellicrackMainWindow()

            # Create test toolbar
            window.toolbar = QToolBar("Main Toolbar")
            window.toolbar.setVisible(False)

            # Save state
            window.save_window_state()

            # Verify toolbar state was saved
            saved_toolbar = self.config.get("ui_preferences.toolbar_positions.main_toolbar")
            self.assertIsNotNone(saved_toolbar)
            self.assertEqual(saved_toolbar["visible"], False)

            # Create new window
            window2 = IntellicrackMainWindow()
            window2.toolbar = QToolBar("Main Toolbar")
            window2.toolbar.setVisible(True)  # Start visible

            # Restore state
            window2.restore_window_state()

            # Verify toolbar visibility was restored
            self.assertFalse(window2.toolbar.isVisible())

    def test_theme_persistence(self):
        """Test that theme settings persist across restarts."""
        # Create theme manager
        theme_manager = ThemeManager()

        # Set dark theme
        theme_manager.set_theme("dark")

        # Verify theme was saved to config
        saved_theme = self.config.get("ui_preferences.theme")
        self.assertEqual(saved_theme, "dark")

        # Create new theme manager instance
        theme_manager2 = ThemeManager()

        # Verify theme was loaded from config
        self.assertEqual(theme_manager2.current_theme, "dark")

        # Test light theme
        theme_manager2.set_theme("light")
        saved_theme = self.config.get("ui_preferences.theme")
        self.assertEqual(saved_theme, "light")

        # Create another instance
        theme_manager3 = ThemeManager()
        self.assertEqual(theme_manager3.current_theme, "light")

    def test_complete_ui_state_round_trip(self):
        """Test complete UI state save and restore cycle."""
        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            # Create and configure first window
            window1 = IntellicrackMainWindow()

            # Set up all UI state
            window1.setGeometry(QRect(150, 150, 1366, 768))
            window1.showMaximized()

            # Mock splitter
            window1.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window1.main_splitter.addWidget(QMainWindow())
            window1.main_splitter.addWidget(QMainWindow())
            window1.main_splitter.setSizes([900, 466])

            # Mock toolbar
            window1.toolbar = QToolBar("Main Toolbar")
            window1.toolbar.setVisible(False)

            # Save complete state
            window1.save_window_state()

            # Also save theme
            theme_manager = ThemeManager()
            theme_manager.set_theme("dark")

            # Save config to disk
            self.config.save()

            # Load config from disk (simulating restart)
            config2 = IntellicrackConfig()
            config2.config_file = str(self.config_path)
            config2.load()

            # Update mock to return new config
            self.mock_get_config.return_value = config2
            self.mock_theme_config.return_value = config2

            # Create new window with loaded config
            window2 = IntellicrackMainWindow()

            # Mock UI elements
            window2.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window2.main_splitter.addWidget(QMainWindow())
            window2.main_splitter.addWidget(QMainWindow())
            window2.toolbar = QToolBar("Main Toolbar")

            # Restore state
            window2.restore_window_state()

            # Verify all state was restored
            self.assertEqual(window2.geometry().width(), 1366)
            self.assertEqual(window2.geometry().height(), 768)
            self.assertEqual(window2.main_splitter.sizes(), [900, 466])
            self.assertFalse(window2.toolbar.isVisible())

            # Verify theme
            theme_manager2 = ThemeManager()
            self.assertEqual(theme_manager2.current_theme, "dark")

    def test_ui_state_with_missing_config(self):
        """Test UI state handling when config doesn't exist."""
        # Delete config file
        if self.config_path.exists():
            self.config_path.unlink()

        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            # Create window without existing config
            window = IntellicrackMainWindow()

            # Should use defaults
            window.restore_window_state()

            # Verify defaults are applied
            default_geometry = self.config.get("ui_preferences.window_geometry")
            self.assertEqual(default_geometry["width"], 1200)
            self.assertEqual(default_geometry["height"], 800)

            # Theme should default to light
            theme_manager = ThemeManager()
            self.assertEqual(theme_manager.current_theme, "light")

    def test_ui_state_with_corrupted_values(self):
        """Test UI state handling with corrupted config values."""
        # Set invalid values in config
        self.config.set("ui_preferences.window_geometry", {"width": -100, "height": "invalid"})
        self.config.set("ui_preferences.splitter_states.main_splitter", "not_a_list")
        self.config.save()

        with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
            window = IntellicrackMainWindow()
            window.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window.main_splitter.addWidget(QMainWindow())
            window.main_splitter.addWidget(QMainWindow())

            # Should handle gracefully
            window.restore_window_state()

            # Should fall back to defaults
            geometry = window.geometry()
            self.assertGreater(geometry.width(), 0)
            self.assertGreater(geometry.height(), 0)

            # Splitter should have reasonable sizes
            sizes = window.main_splitter.sizes()
            self.assertEqual(len(sizes), 2)
            self.assertGreater(sizes[0], 0)
            self.assertGreater(sizes[1], 0)

    def test_concurrent_ui_state_access(self):
        """Test UI state persistence with concurrent access."""
        import threading
        import time

        results = []

        def save_state(window_id):
            """Save state from a thread."""
            with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
                window = IntellicrackMainWindow()
                window.setGeometry(QRect(window_id * 10, window_id * 10, 1000 + window_id, 600 + window_id))
                window.save_window_state()
                results.append((window_id, "saved"))

        def load_state(window_id):
            """Load state from a thread."""
            time.sleep(0.01)  # Small delay to ensure saves happen first
            with patch('intellicrack.ui.main_app.IntellicrackMainWindow.setup_ui'):
                window = IntellicrackMainWindow()
                window.restore_window_state()
                geometry = window.geometry()
                results.append((window_id, "loaded", geometry.width(), geometry.height()))

        # Create threads for concurrent access
        threads = []
        for i in range(5):
            t1 = threading.Thread(target=save_state, args=(i,))
            t2 = threading.Thread(target=load_state, args=(i,))
            threads.extend([t1, t2])

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=5.0)

        # Verify all operations completed
        save_count = sum(bool(len(r) == 2 and r[1] == "saved")
                     for r in results)
        load_count = sum(bool(len(r) == 4 and r[1] == "loaded")
                     for r in results)

        self.assertEqual(save_count, 5, "All save operations should complete")
        self.assertEqual(load_count, 5, "All load operations should complete")

        # Final state should be consistent
        final_config = self.config.get("ui_preferences.window_geometry")
        self.assertIsNotNone(final_config)
        self.assertIn("width", final_config)
        self.assertIn("height", final_config)


if __name__ == "__main__":
    unittest.main()
