"""Production-ready tests for GhidraScriptSelector.

Tests REAL script management and selection logic.
Tests MUST FAIL if script filtering and validation doesn't work properly.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem

from intellicrack.ui.dialogs.ghidra_script_selector import GhidraScriptSelector, ScriptInfoWidget
from intellicrack.utils.tools.ghidra_script_manager import GhidraScript


class FakeGhidraScriptManager:
    """Test double for GhidraScriptManager that manages scripts without filesystem dependencies."""

    def __init__(self) -> None:
        self.scripts: dict[str, GhidraScript] = {}
        self.scan_called = False
        self.force_rescan = False

    def scan_scripts(self, force_rescan: bool = False) -> dict[str, GhidraScript]:
        self.scan_called = True
        self.force_rescan = force_rescan
        return self.scripts

    def get_scripts_by_category(self) -> dict[str, list[GhidraScript]]:
        categorized: dict[str, list[GhidraScript]] = {}
        for script in self.scripts.values():
            if script.category not in categorized:
                categorized[script.category] = []
            categorized[script.category].append(script)
        return categorized

    def search_scripts(self, query: str) -> list[GhidraScript]:
        query_lower = query.lower()
        return [
            script for script in self.scripts.values()
            if query_lower in script.name.lower() or query_lower in script.description.lower()
        ]

    def get_script(self, path: str) -> GhidraScript | None:
        return self.scripts.get(path)

    def add_script(self, script: GhidraScript) -> None:
        self.scripts[script.path] = script

    def add_user_script(self, file_path: str) -> GhidraScript | None:
        try:
            script = GhidraScript(file_path)
            self.add_script(script)
            return script
        except Exception:
            return None


def create_ghidra_script(
    path: str,
    name: str,
    description: str,
    category: str,
    author: str = "TestAuthor",
    version: str = "1.0",
    script_type: str = "java",
    size: int = 1000,
    tags: list[str] | None = None,
    is_valid: bool = True,
    validation_errors: list[str] | None = None,
) -> GhidraScript:
    """Factory function to create GhidraScript instances for testing."""
    script = object.__new__(GhidraScript)
    script.path = path
    script.name = name
    script.description = description
    script.category = category
    script.author = author
    script.version = version
    script.type = script_type
    script.size = size
    script.last_modified = datetime.now()
    script.tags = tags or []
    script.is_valid = is_valid
    script.validation_errors = validation_errors or []
    script.filename = Path(path).name
    script.extension = Path(path).suffix
    script.directory = str(Path(path).parent)
    return script


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    """Create QApplication instance for all tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
        app.setApplicationName("IntellicrackGhidraScriptTest")
        return app
    assert isinstance(app, QApplication), "Expected QApplication instance"
    app.setApplicationName("IntellicrackGhidraScriptTest")
    return app


@pytest.fixture
def valid_java_script_content() -> str:
    """Valid Java Ghidra script content."""
    return '''//Analyzes binary for license checks
//@category Protection
//@author TestAuthor
//@version 1.0
import ghidra.app.script.GhidraScript;

public class TestAnalysis extends GhidraScript {
    public void run() throws Exception {
        println("Analyzing for license checks...");
    }
}'''


@pytest.fixture
def valid_python_script_content() -> str:
    """Valid Python Ghidra script content."""
    return '''#Searches for anti-debug code
#@category Protection
#@author TestAuthor
#@version 1.0

def run():
    print("Searching for anti-debug...")
'''


@pytest.fixture
def invalid_script_content() -> str:
    """Invalid script content without required metadata."""
    return '''public class Invalid {
    // Missing Ghidra script metadata
}'''


@pytest.fixture
def sample_valid_script(tmp_path: Path, valid_java_script_content: str) -> GhidraScript:
    """Create a valid GhidraScript instance for testing."""
    script_file = tmp_path / "ValidScript.java"
    script_file.write_text(valid_java_script_content)

    return create_ghidra_script(
        path=str(script_file),
        name="ValidScript",
        description="Analyzes binary for license checks",
        category="Protection",
        author="TestAuthor",
        version="1.0",
        script_type="java",
        size=len(valid_java_script_content),
        tags=["license", "protection"],
        is_valid=True,
        validation_errors=[],
    )


@pytest.fixture
def sample_invalid_script(tmp_path: Path, invalid_script_content: str) -> GhidraScript:
    """Create an invalid GhidraScript instance for testing."""
    script_file = tmp_path / "InvalidScript.java"
    script_file.write_text(invalid_script_content)

    return create_ghidra_script(
        path=str(script_file),
        name="InvalidScript",
        description="",
        category="Uncategorized",
        author="Unknown",
        version="",
        script_type="java",
        size=len(invalid_script_content),
        tags=[],
        is_valid=False,
        validation_errors=["Missing required @category metadata", "Missing description"],
    )


@pytest.fixture
def fake_script_manager() -> FakeGhidraScriptManager:
    """Create fake script manager for testing."""
    return FakeGhidraScriptManager()


class TestScriptInfoWidget:
    """Test ScriptInfoWidget display logic."""

    def test_widget_initializes_with_empty_state(self, qapp: QApplication) -> None:
        """Widget initializes with empty/default state."""
        widget = ScriptInfoWidget()

        assert widget.current_script is None
        assert widget.name_label.text() == "Select a script"
        assert widget.author_label.text() == "Author: -"
        assert widget.category_label.text() == "Category: -"
        assert widget.validation_label.text() == "Not validated"

    def test_update_script_info_displays_valid_script(self, qapp: QApplication, sample_valid_script: GhidraScript) -> None:
        """Update script info displays all valid script details correctly."""
        widget = ScriptInfoWidget()

        widget.update_script_info(sample_valid_script)

        assert widget.current_script == sample_valid_script
        assert widget.name_label.text() == "ValidScript"
        assert "TestAuthor" in widget.author_label.text()
        assert "Protection" in widget.category_label.text()
        assert "1.0" in widget.version_label.text()
        assert "JAVA" in widget.type_label.text()
        assert "Analyzes binary for license checks" in widget.description_text.toPlainText()
        assert "Valid" in widget.validation_label.text()
        assert not widget.validation_errors.isVisible()

    def test_update_script_info_displays_invalid_script(self, qapp: QApplication, sample_invalid_script: GhidraScript) -> None:
        """Update script info displays invalid script with validation errors."""
        widget = ScriptInfoWidget()

        widget.update_script_info(sample_invalid_script)

        assert widget.current_script == sample_invalid_script
        assert widget.name_label.text() == "InvalidScript"
        assert "Invalid" in widget.validation_label.text()
        assert widget.validation_errors.isVisible()
        assert "Missing required @category metadata" in widget.validation_errors.toPlainText()

    def test_update_script_info_with_none_clears_display(self, qapp: QApplication, sample_valid_script: GhidraScript) -> None:
        """Update script info with None clears all displayed information."""
        widget = ScriptInfoWidget()

        widget.update_script_info(sample_valid_script)
        widget.update_script_info(None)

        assert widget.current_script is None
        assert widget.name_label.text() == "Select a script"
        assert widget.author_label.text() == "Author: -"
        assert widget.description_text.toPlainText() == ""

    def test_update_script_info_formats_file_size_correctly(self, qapp: QApplication, sample_valid_script: GhidraScript) -> None:
        """Update script info formats file size appropriately (bytes vs KB)."""
        widget = ScriptInfoWidget()

        small_script = create_ghidra_script(
            path="/test/small.java",
            name="Small",
            description="Test",
            category="Test",
            author="Author",
            version="1.0",
            script_type="java",
            size=500,
            is_valid=True,
        )

        widget.update_script_info(small_script)
        assert "500 bytes" in widget.size_label.text()

        large_script = create_ghidra_script(
            path="/test/large.java",
            name="Large",
            description="Test",
            category="Test",
            author="Author",
            version="1.0",
            script_type="java",
            size=5000,
            is_valid=True,
        )

        widget.update_script_info(large_script)
        assert "KB" in widget.size_label.text()

    def test_update_script_info_displays_tags(self, qapp: QApplication, sample_valid_script: GhidraScript) -> None:
        """Update script info displays tags correctly."""
        widget = ScriptInfoWidget()

        widget.update_script_info(sample_valid_script)

        assert "license" in widget.tags_label.text()
        assert "protection" in widget.tags_label.text()


class TestGhidraScriptSelector:
    """Test GhidraScriptSelector dialog logic."""

    def test_dialog_initializes_correctly(self, qapp: QApplication, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog initializes with correct default state."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        assert dialog.windowTitle() == "Select Ghidra Script"
        assert not dialog.show_invalid
        assert dialog.selected_script_path is None
        assert not dialog.select_btn.isEnabled()
        assert fake_script_manager.scan_called

    def test_show_invalid_scripts_filter(self, qapp: QApplication, sample_valid_script: GhidraScript, sample_invalid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Show invalid scripts checkbox filters displayed scripts correctly."""
        fake_script_manager.add_script(sample_valid_script)
        fake_script_manager.add_script(sample_invalid_script)

        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()
        dialog.show_invalid = False
        dialog._populate_tree()

        root_count = dialog.script_tree.topLevelItemCount()
        assert root_count == 1

        category_item = dialog.script_tree.topLevelItem(0)
        assert category_item is not None, "Expected category item 0"
        visible_count = category_item.childCount()
        assert visible_count == 1

        dialog.show_invalid = True
        dialog._populate_tree()

        category_item = dialog.script_tree.topLevelItem(0)
        assert category_item is not None, "Expected category item 0"
        visible_count = category_item.childCount()
        assert visible_count == 2

    def test_category_filter_filters_scripts(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Category filter correctly filters displayed scripts."""
        protection_script = sample_valid_script
        analysis_script = create_ghidra_script(
            path="/test/analysis.java",
            name="AnalysisScript",
            description="Analyzes binary",
            category="Analysis",
            author="Author",
            version="1.0",
            script_type="java",
            size=1000,
            is_valid=True,
        )

        fake_script_manager.add_script(protection_script)
        fake_script_manager.add_script(analysis_script)

        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()
        dialog._populate_tree()

        assert dialog.script_tree.topLevelItemCount() == 2

        dialog.category_filter.setCurrentText("Protection")
        dialog._on_category_changed("Protection")

        found_protection = False
        for i in range(dialog.script_tree.topLevelItemCount()):
            item = dialog.script_tree.topLevelItem(i)
            if item is not None and item.text(0) == "ValidScript":
                found_protection = True

        assert found_protection

    def test_search_filters_scripts_by_name(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Search input filters scripts by name correctly."""
        fake_script_manager.add_script(sample_valid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        dialog.search_input.setText("Valid")
        dialog._populate_tree()

        found = False
        for i in range(dialog.script_tree.topLevelItemCount()):
            item = dialog.script_tree.topLevelItem(i)
            if item is not None and item.text(0) == "ValidScript":
                found = True
                break

        assert found

    def test_script_selection_updates_info_widget(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Selecting a script updates the info widget with script details."""
        fake_script_manager.add_script(sample_valid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        item = QTreeWidgetItem(["ValidScript", "JAVA", "Valid"])
        item.setData(0, Qt.ItemDataRole.UserRole, sample_valid_script.path)
        dialog.script_tree.addTopLevelItem(item)

        dialog.script_tree.setCurrentItem(item)
        dialog._on_selection_changed()

        assert dialog.info_widget.current_script == sample_valid_script
        assert dialog.select_btn.isEnabled()
        assert dialog.selected_script_path == sample_valid_script.path

    def test_invalid_script_selection_disables_select_button(self, qapp: QApplication, sample_invalid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Selecting an invalid script disables the select button."""
        fake_script_manager.add_script(sample_invalid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        item = QTreeWidgetItem(["InvalidScript", "JAVA", "Invalid"])
        item.setData(0, Qt.ItemDataRole.UserRole, sample_invalid_script.path)
        dialog.script_tree.addTopLevelItem(item)

        dialog.script_tree.setCurrentItem(item)
        dialog._on_selection_changed()

        assert not dialog.select_btn.isEnabled()

    def test_select_button_emits_script_selected_signal(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Select button emits script_selected signal with correct path."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()
        dialog.selected_script_path = sample_valid_script.path

        emitted_paths: list[str] = []
        dialog.script_selected.connect(lambda path: emitted_paths.append(path))

        dialog._on_select_clicked()

        assert len(emitted_paths) == 1
        assert emitted_paths[0] == sample_valid_script.path

    def test_use_default_button_emits_default_marker(self, qapp: QApplication, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Use default button emits special __DEFAULT__ marker."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        emitted_paths: list[str] = []
        dialog.script_selected.connect(lambda path: emitted_paths.append(path))

        dialog._use_default_script()

        assert len(emitted_paths) == 1
        assert emitted_paths[0] == "__DEFAULT__"

    def test_double_click_selects_valid_script(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Double-clicking a valid script selects it and emits signal."""
        fake_script_manager.add_script(sample_valid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        emitted_paths: list[str] = []
        dialog.script_selected.connect(lambda path: emitted_paths.append(path))

        item = QTreeWidgetItem(["ValidScript", "JAVA", "Valid"])
        item.setData(0, Qt.ItemDataRole.UserRole, sample_valid_script.path)

        dialog.selected_script_path = sample_valid_script.path
        dialog._on_item_double_clicked(item, 0)

        assert len(emitted_paths) == 1
        assert emitted_paths[0] == sample_valid_script.path

    def test_refresh_button_rescans_scripts(self, qapp: QApplication, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Refresh button triggers script rescan."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        initial_scan_called = fake_script_manager.scan_called
        fake_script_manager.scan_called = False

        dialog._refresh_scripts()

        assert fake_script_manager.scan_called
        assert fake_script_manager.force_rescan

    def test_create_script_item_sets_valid_script_formatting(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Create script item sets correct formatting for valid scripts."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        item = dialog._create_script_item(sample_valid_script)

        assert item.text(0) == "ValidScript"
        assert item.text(1) == "JAVA"
        assert "Valid" in item.text(2)
        assert item.data(0, Qt.ItemDataRole.UserRole) == sample_valid_script.path

    def test_create_script_item_sets_invalid_script_formatting(self, qapp: QApplication, sample_invalid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Create script item sets correct formatting for invalid scripts."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        item = dialog._create_script_item(sample_invalid_script)

        assert item.text(0) == "InvalidScript"
        assert "Invalid" in item.text(2)

    def test_get_selected_script_returns_selected_path(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Get selected script returns the currently selected script path."""
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        assert dialog.get_selected_script() is None

        dialog.selected_script_path = sample_valid_script.path
        assert dialog.get_selected_script() == sample_valid_script.path


class TestGhidraScriptSelectorIntegration:
    """Integration tests for complete script selection workflows."""

    def test_complete_script_selection_workflow(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Complete workflow of browsing, selecting, and confirming a script."""
        fake_script_manager.add_script(sample_valid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        emitted_paths: list[str] = []
        dialog.script_selected.connect(lambda path: emitted_paths.append(path))

        dialog._populate_tree()

        category_item = dialog.script_tree.topLevelItem(0)
        assert category_item is not None, "Expected category item 0"
        script_item = category_item.child(0)

        dialog.script_tree.setCurrentItem(script_item)
        dialog._on_selection_changed()

        assert dialog.selected_script_path == sample_valid_script.path
        assert dialog.select_btn.isEnabled()

        dialog._on_select_clicked()

        assert len(emitted_paths) == 1
        assert emitted_paths[0] == sample_valid_script.path

    def test_search_and_select_workflow(self, qapp: QApplication, sample_valid_script: GhidraScript, fake_script_manager: FakeGhidraScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """Complete workflow of searching for and selecting a script."""
        fake_script_manager.add_script(sample_valid_script)
        monkeypatch.setattr("intellicrack.ui.dialogs.ghidra_script_selector.get_script_manager", lambda: fake_script_manager)

        dialog = GhidraScriptSelector()

        dialog.search_input.setText("valid")
        dialog._populate_tree()

        assert dialog.script_tree.topLevelItemCount() > 0

        first_item = dialog.script_tree.topLevelItem(0)
        dialog.script_tree.setCurrentItem(first_item)
        dialog._on_selection_changed()

        assert dialog.info_widget.current_script == sample_valid_script
