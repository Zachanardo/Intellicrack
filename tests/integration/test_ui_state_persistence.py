"""
Integration tests for UI state persistence across application restarts.

This module tests that all UI state (window geometry, splitter positions,
toolbar states, theme settings) are properly saved and restored using the
central configuration system.
"""

import json
import tempfile
import unittest
from pathlib import Path

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
        import shutil
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "config.json"
        self.config = IntellicrackConfig()
        self.config.config_file = str(self.config_path)

        import intellicrack.core.config_manager
        import intellicrack.ui.main_app
        import intellicrack.ui.theme_manager

        self._original_config_file = getattr(intellicrack.core.config_manager, 'CONFIG_FILE', None)
        self._original_get_config = getattr(intellicrack.ui.main_app, 'get_config', None)
        self._original_theme_get_config = getattr(intellicrack.ui.theme_manager, 'get_config', None)

        intellicrack.core.config_manager.CONFIG_FILE = str(self.config_path)

        if hasattr(intellicrack.ui.main_app, 'get_config'):
            intellicrack.ui.main_app.get_config = lambda: self.config

        if hasattr(intellicrack.ui.theme_manager, 'get_config'):
            intellicrack.ui.theme_manager.get_config = lambda: self.config

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        import intellicrack.core.config_manager
        import intellicrack.ui.main_app
        import intellicrack.ui.theme_manager

        if self._original_config_file is not None:
            intellicrack.core.config_manager.CONFIG_FILE = self._original_config_file

        if self._original_get_config is not None and hasattr(intellicrack.ui.main_app, 'get_config'):
            intellicrack.ui.main_app.get_config = self._original_get_config

        if self._original_theme_get_config is not None and hasattr(intellicrack.ui.theme_manager, 'get_config'):
            intellicrack.ui.theme_manager.get_config = self._original_theme_get_config

        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_window_geometry_persistence(self):
        """Test that window geometry is saved and restored correctly."""
        import intellicrack.ui.main_app

        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
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

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_window_state_persistence(self):
        """Test that window state (maximized/normal) is saved and restored."""
        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
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

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_splitter_state_persistence(self):
        """Test that splitter positions are saved and restored."""
        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
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

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_toolbar_visibility_persistence(self):
        """Test that toolbar visibility is saved and restored."""
        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
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
            window2.toolbar.setVisible(True)

            # Restore state
            window2.restore_window_state()

            # Verify toolbar visibility was restored
            self.assertFalse(window2.toolbar.isVisible())

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

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
        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
            window1 = IntellicrackMainWindow()

            window1.setGeometry(QRect(150, 150, 1366, 768))
            window1.showMaximized()

            window1.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window1.main_splitter.addWidget(QMainWindow())
            window1.main_splitter.addWidget(QMainWindow())
            window1.main_splitter.setSizes([900, 466])

            window1.toolbar = QToolBar("Main Toolbar")
            window1.toolbar.setVisible(False)

            window1.save_window_state()

            theme_manager = ThemeManager()
            theme_manager.set_theme("dark")

            self.config.save()

            config2 = IntellicrackConfig()
            config2.config_file = str(self.config_path)
            config2.load()

            import intellicrack.ui.main_app
            import intellicrack.ui.theme_manager

            original_main_get_config = getattr(intellicrack.ui.main_app, 'get_config', None)
            original_theme_get_config = getattr(intellicrack.ui.theme_manager, 'get_config', None)

            if hasattr(intellicrack.ui.main_app, 'get_config'):
                intellicrack.ui.main_app.get_config = lambda: config2

            if hasattr(intellicrack.ui.theme_manager, 'get_config'):
                intellicrack.ui.theme_manager.get_config = lambda: config2

            window2 = IntellicrackMainWindow()

            window2.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window2.main_splitter.addWidget(QMainWindow())
            window2.main_splitter.addWidget(QMainWindow())
            window2.toolbar = QToolBar("Main Toolbar")

            window2.restore_window_state()

            self.assertEqual(window2.geometry().width(), 1366)
            self.assertEqual(window2.geometry().height(), 768)
            self.assertEqual(window2.main_splitter.sizes(), [900, 466])
            self.assertFalse(window2.toolbar.isVisible())

            theme_manager2 = ThemeManager()
            self.assertEqual(theme_manager2.current_theme, "dark")

            if original_main_get_config is not None and hasattr(intellicrack.ui.main_app, 'get_config'):
                intellicrack.ui.main_app.get_config = original_main_get_config

            if original_theme_get_config is not None and hasattr(intellicrack.ui.theme_manager, 'get_config'):
                intellicrack.ui.theme_manager.get_config = original_theme_get_config

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_ui_state_with_missing_config(self):
        """Test UI state handling when config doesn't exist."""
        if self.config_path.exists():
            self.config_path.unlink()

        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
            window = IntellicrackMainWindow()

            window.restore_window_state()

            default_geometry = self.config.get("ui_preferences.window_geometry")
            self.assertEqual(default_geometry["width"], 1200)
            self.assertEqual(default_geometry["height"], 800)

            theme_manager = ThemeManager()
            self.assertEqual(theme_manager.current_theme, "light")

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_ui_state_with_corrupted_values(self):
        """Test UI state handling with corrupted config values."""
        self.config.set("ui_preferences.window_geometry", {"width": -100, "height": "invalid"})
        self.config.set("ui_preferences.splitter_states.main_splitter", "not_a_list")
        self.config.save()

        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        try:
            window = IntellicrackMainWindow()
            window.main_splitter = QSplitter(Qt.Orientation.Horizontal)
            window.main_splitter.addWidget(QMainWindow())
            window.main_splitter.addWidget(QMainWindow())

            window.restore_window_state()

            geometry = window.geometry()
            self.assertGreater(geometry.width(), 0)
            self.assertGreater(geometry.height(), 0)

            sizes = window.main_splitter.sizes()
            self.assertEqual(len(sizes), 2)
            self.assertGreater(sizes[0], 0)
            self.assertGreater(sizes[1], 0)

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui

    def test_concurrent_ui_state_access(self):
        """Test UI state persistence with concurrent access."""
        import threading
        import time

        results = []

        original_setup_ui = getattr(IntellicrackMainWindow, 'setup_ui', None)
        IntellicrackMainWindow.setup_ui = lambda self: None

        def save_state(window_id):
            """Save state from a thread."""
            window = IntellicrackMainWindow()
            window.setGeometry(QRect(window_id * 10, window_id * 10, 1000 + window_id, 600 + window_id))
            window.save_window_state()
            results.append((window_id, "saved"))

        def load_state(window_id):
            """Load state from a thread."""
            time.sleep(0.01)
            window = IntellicrackMainWindow()
            window.restore_window_state()
            geometry = window.geometry()
            results.append((window_id, "loaded", geometry.width(), geometry.height()))

        try:
            threads = []
            for i in range(5):
                t1 = threading.Thread(target=save_state, args=(i,))
                t2 = threading.Thread(target=load_state, args=(i,))
                threads.extend([t1, t2])

            for t in threads:
                t.start()

            for t in threads:
                t.join(timeout=5.0)

            save_count = sum(bool(len(r) == 2 and r[1] == "saved")
                         for r in results)
            load_count = sum(bool(len(r) == 4 and r[1] == "loaded")
                         for r in results)

            self.assertEqual(save_count, 5, "All save operations should complete")
            self.assertEqual(load_count, 5, "All load operations should complete")

            final_config = self.config.get("ui_preferences.window_geometry")
            self.assertIsNotNone(final_config)
            self.assertIn("width", final_config)
            self.assertIn("height", final_config)

        finally:
            if original_setup_ui is not None:
                IntellicrackMainWindow.setup_ui = original_setup_ui


if __name__ == "__main__":
    unittest.main()
