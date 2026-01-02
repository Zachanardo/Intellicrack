"""Production-ready tests for ProgramSelectorDialog - Program discovery wizard validation.

This module validates ProgramSelectorDialog's complete functionality including:
- Wizard initialization and multi-page navigation
- File selection page with validation
- Program binary file browsing and selection
- Installation folder analysis for licensing files
- License file pattern detection (license, eula, copyright, etc.)
- File metadata extraction and display
- Double-click licensing file opening
- Analysis page information display
- Program data retrieval for licensing cracking workflow
- File size formatting utility
"""

import tempfile
from pathlib import Path
from typing import Any, Optional

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox, QWizard

from intellicrack.ui.dialogs.program_selector_dialog import (
    AnalysisPage,
    FileSelectionPage,
    ProgramSelectorDialog,
    show_program_selector,
)


class FakeFileDialog:
    """Real test double for QFileDialog with call tracking."""

    def __init__(self) -> None:
        self.get_open_filename_calls: list[dict[str, Any]] = []
        self.return_value: tuple[str, str] = ("", "")

    def set_return_value(self, file_path: str, selected_filter: str = "") -> None:
        """Configure return value for getOpenFileName."""
        self.return_value = (file_path, selected_filter)

    @staticmethod
    def getOpenFileName(
        parent: Any = None,
        caption: str = "",
        directory: str = "",
        filter: str = "",
        initial_filter: str = "",
    ) -> tuple[str, str]:
        """Real implementation that returns configured value."""
        instance = FakeFileDialog._instance
        if instance is None:
            return ("", "")

        instance.get_open_filename_calls.append(
            {
                "parent": parent,
                "caption": caption,
                "directory": directory,
                "filter": filter,
                "initial_filter": initial_filter,
            }
        )
        return instance.return_value

    _instance: Optional["FakeFileDialog"] = None


class FakeMessageBox:
    """Real test double for QMessageBox with call tracking."""

    def __init__(self) -> None:
        self.warning_calls: list[dict[str, Any]] = []

    @staticmethod
    def warning(
        parent: Any,
        title: str,
        text: str,
        buttons: Any = None,
        default_button: Any = None,
    ) -> Any:
        """Real implementation that tracks warning calls."""
        instance = FakeMessageBox._instance
        if instance is None:
            return None

        instance.warning_calls.append(
            {
                "parent": parent,
                "title": title,
                "text": text,
                "buttons": buttons,
                "default_button": default_button,
            }
        )
        return None

    _instance: Optional["FakeMessageBox"] = None


class FakeProgramSelectorDialog:
    """Real test double for ProgramSelectorDialog with call tracking."""

    def __init__(self) -> None:
        self.exec_calls: int = 0
        self.exec_return_value: int = 0
        self.get_selected_program_data_calls: int = 0
        self.program_data: Optional[dict[str, Any]] = None

    def exec(self) -> int:
        """Real implementation that returns configured value."""
        self.exec_calls += 1
        return self.exec_return_value

    def get_selected_program_data(self) -> Optional[dict[str, Any]]:
        """Real implementation that returns configured program data."""
        self.get_selected_program_data_calls += 1
        return self.program_data

    def set_exec_return_value(self, value: int) -> None:
        """Configure return value for exec()."""
        self.exec_return_value = value

    def set_program_data(self, data: Optional[dict[str, Any]]) -> None:
        """Configure return value for get_selected_program_data()."""
        self.program_data = data


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def temp_exe_file(tmp_path: Path) -> Path:
    """Create temporary executable file for testing."""
    exe_file = tmp_path / "TestApp.exe"
    exe_content = b"MZ\x90\x00"  # DOS header
    exe_content += b"\x00" * 2000
    exe_file.write_bytes(exe_content)
    return exe_file


@pytest.fixture
def temp_installation_folder(tmp_path: Path, temp_exe_file: Path) -> Path:
    """Create temporary installation folder with licensing files."""
    install_dir = temp_exe_file.parent

    (install_dir / "LICENSE.txt").write_text("MIT License\n\nCopyright (c) 2025")
    (install_dir / "EULA.txt").write_text("End User License Agreement")
    (install_dir / "README.md").write_text("# Test Application\n\nDocumentation here")
    (install_dir / "COPYRIGHT").write_text("Copyright information")

    subdoc_dir = install_dir / "docs"
    subdoc_dir.mkdir()
    (subdoc_dir / "license_terms.txt").write_text("Licensing terms and conditions")

    return install_dir


@pytest.fixture
def program_selector_dialog(qapp: QApplication) -> ProgramSelectorDialog:
    """Create ProgramSelectorDialog for testing."""
    return ProgramSelectorDialog()


@pytest.fixture
def file_selection_page(program_selector_dialog: ProgramSelectorDialog) -> FileSelectionPage:
    """Get FileSelectionPage from wizard."""
    return program_selector_dialog.file_selection_page


@pytest.fixture
def analysis_page(program_selector_dialog: ProgramSelectorDialog) -> AnalysisPage:
    """Get AnalysisPage from wizard."""
    return program_selector_dialog.analysis_page


class TestProgramSelectorDialogInitialization:
    """Test ProgramSelectorDialog initialization and setup."""

    def test_dialog_window_title_is_set(self, program_selector_dialog: ProgramSelectorDialog) -> None:
        """Dialog window title is set to 'Program Selection Wizard'."""
        assert program_selector_dialog.windowTitle() == "Program Selection Wizard"

    def test_dialog_minimum_size_configured(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Dialog has minimum size of 800x600 pixels."""
        assert program_selector_dialog.minimumWidth() == 800
        assert program_selector_dialog.minimumHeight() == 600

    def test_dialog_has_two_pages(self, program_selector_dialog: ProgramSelectorDialog) -> None:
        """Dialog wizard contains exactly two pages."""
        assert program_selector_dialog.pageIds() == [0, 1]

    def test_dialog_uses_modern_wizard_style(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Dialog uses modern wizard style."""
        assert program_selector_dialog.wizardStyle() == QWizard.WizardStyle.ModernStyle

    def test_dialog_disables_help_button(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Dialog has help button disabled."""
        assert not program_selector_dialog.testOption(QWizard.WizardOption.HaveHelpButton)

    def test_selected_program_initially_none(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Selected program is None on initialization."""
        assert program_selector_dialog.selected_program is None

    def test_file_filters_configured(self, program_selector_dialog: ProgramSelectorDialog) -> None:
        """Dialog has file filters for different platforms."""
        assert "All Executables" in program_selector_dialog.file_filters
        assert "Windows" in program_selector_dialog.file_filters
        assert "Linux" in program_selector_dialog.file_filters
        assert "macOS" in program_selector_dialog.file_filters

    def test_windows_filter_includes_exe_dll(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Windows file filter includes exe and dll extensions."""
        windows_filter = program_selector_dialog.file_filters["Windows"]
        assert "*.exe" in windows_filter
        assert "*.dll" in windows_filter


class TestFileSelectionPage:
    """Test FileSelectionPage functionality."""

    def test_page_title_is_set(self, file_selection_page: FileSelectionPage) -> None:
        """File selection page has correct title."""
        assert file_selection_page.title() == "Select Program File"

    def test_page_has_subtitle(self, file_selection_page: FileSelectionPage) -> None:
        """File selection page has subtitle with instructions."""
        subtitle = file_selection_page.subTitle()
        assert "executable" in subtitle.lower()

    def test_page_has_file_path_edit(self, file_selection_page: FileSelectionPage) -> None:
        """Page has file path line edit widget."""
        assert file_selection_page.file_path_edit is not None

    def test_page_has_browse_button(self, file_selection_page: FileSelectionPage) -> None:
        """Page has browse button for file selection."""
        assert file_selection_page.browse_btn is not None
        assert "Browse" in file_selection_page.browse_btn.text()

    def test_page_incomplete_without_file(self, file_selection_page: FileSelectionPage) -> None:
        """Page is incomplete when no file is selected."""
        file_selection_page.file_path_edit.setText("")
        assert not file_selection_page.isComplete()

    def test_page_incomplete_with_nonexistent_file(
        self, file_selection_page: FileSelectionPage
    ) -> None:
        """Page is incomplete when nonexistent file path is entered."""
        file_selection_page.file_path_edit.setText("/nonexistent/file.exe")
        QApplication.processEvents()
        assert not file_selection_page.isComplete()

    def test_page_complete_with_valid_file(
        self, file_selection_page: FileSelectionPage, temp_exe_file: Path
    ) -> None:
        """Page is complete when valid executable file is selected."""
        file_selection_page.file_path_edit.setText(str(temp_exe_file))
        QApplication.processEvents()
        assert file_selection_page.isComplete()

    def test_browse_for_file_opens_dialog(
        self, file_selection_page: FileSelectionPage, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Browse button opens file selection dialog."""
        fake_dialog = FakeFileDialog()
        fake_dialog.set_return_value("", "")
        FakeFileDialog._instance = fake_dialog

        monkeypatch.setattr(QFileDialog, "getOpenFileName", FakeFileDialog.getOpenFileName)
        file_selection_page.browse_for_file()

        assert len(fake_dialog.get_open_filename_calls) == 1
        FakeFileDialog._instance = None

    def test_browse_for_file_sets_path(
        self,
        file_selection_page: FileSelectionPage,
        temp_exe_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selecting file in browse dialog sets file path."""
        fake_dialog = FakeFileDialog()
        fake_dialog.set_return_value(str(temp_exe_file), "")
        FakeFileDialog._instance = fake_dialog

        monkeypatch.setattr(QFileDialog, "getOpenFileName", FakeFileDialog.getOpenFileName)
        file_selection_page.browse_for_file()

        assert file_selection_page.file_path_edit.text() == str(temp_exe_file)
        FakeFileDialog._instance = None

    def test_validate_file_path_updates_wizard_state(
        self,
        file_selection_page: FileSelectionPage,
        program_selector_dialog: ProgramSelectorDialog,
        temp_exe_file: Path,
    ) -> None:
        """Valid file path updates wizard selected program."""
        file_selection_page.file_path_edit.setText(str(temp_exe_file))
        QApplication.processEvents()
        assert program_selector_dialog.selected_program == str(temp_exe_file)

    def test_get_selected_file_returns_path(
        self, file_selection_page: FileSelectionPage, temp_exe_file: Path
    ) -> None:
        """Get selected file returns entered file path."""
        file_selection_page.file_path_edit.setText(str(temp_exe_file))
        assert file_selection_page.get_selected_file() == str(temp_exe_file)

    def test_get_selected_file_strips_whitespace(
        self, file_selection_page: FileSelectionPage
    ) -> None:
        """Get selected file strips leading and trailing whitespace."""
        file_selection_page.file_path_edit.setText("  /path/to/file.exe  ")
        result = file_selection_page.get_selected_file()
        assert result == "/path/to/file.exe"


class TestAnalysisPage:
    """Test AnalysisPage functionality."""

    def test_page_title_is_set(self, analysis_page: AnalysisPage) -> None:
        """Analysis page has correct title."""
        assert analysis_page.title() == "Installation Analysis"

    def test_page_has_subtitle(self, analysis_page: AnalysisPage) -> None:
        """Analysis page has subtitle describing analysis."""
        subtitle = analysis_page.subTitle()
        assert "installation folder" in subtitle.lower()

    def test_page_is_final_page(self, analysis_page: AnalysisPage) -> None:
        """Analysis page is marked as final wizard page."""
        assert analysis_page.isFinalPage()

    def test_page_has_program_info_label(self, analysis_page: AnalysisPage) -> None:
        """Page has program information display label."""
        assert analysis_page.program_info is not None

    def test_page_has_licensing_tree(self, analysis_page: AnalysisPage) -> None:
        """Page has licensing files tree widget."""
        assert analysis_page.licensing_tree is not None
        headers = [
            analysis_page.licensing_tree.headerItem().text(i)
            for i in range(analysis_page.licensing_tree.columnCount())
        ]
        assert "File" in headers
        assert "Type" in headers

    def test_format_file_size_bytes(self, analysis_page: AnalysisPage) -> None:
        """File size formatting handles bytes correctly."""
        size_str = analysis_page.format_file_size(512)
        assert "512" in size_str
        assert "B" in size_str

    def test_format_file_size_kilobytes(self, analysis_page: AnalysisPage) -> None:
        """File size formatting handles kilobytes correctly."""
        size_str = analysis_page.format_file_size(2048)
        assert "2.0" in size_str
        assert "KB" in size_str

    def test_format_file_size_megabytes(self, analysis_page: AnalysisPage) -> None:
        """File size formatting handles megabytes correctly."""
        size_str = analysis_page.format_file_size(1024 * 1024 * 5)
        assert "5.0" in size_str
        assert "MB" in size_str

    def test_analyze_installation_folder_finds_license_files(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis discovers licensing files."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        licensing_files = analysis_page.get_licensing_files()
        assert len(licensing_files) > 0

        file_names = [f["name"] for f in licensing_files]
        assert "LICENSE.txt" in file_names

    def test_analyze_installation_folder_detects_eula(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis detects EULA files."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        licensing_files = analysis_page.get_licensing_files()

        eula_files = [f for f in licensing_files if "EULA" in f["name"]]
        assert eula_files

    def test_analyze_installation_folder_detects_copyright(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis detects copyright files."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        licensing_files = analysis_page.get_licensing_files()

        copyright_files = [f for f in licensing_files if "COPYRIGHT" in f["name"]]
        assert copyright_files

    def test_analyze_installation_folder_assigns_priority(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis assigns priority to files."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        licensing_files = analysis_page.get_licensing_files()

        for file_info in licensing_files:
            assert "priority" in file_info
            assert isinstance(file_info["priority"], int)
            assert file_info["priority"] >= 1

    def test_analyze_installation_folder_populates_tree(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis populates tree widget."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        assert analysis_page.licensing_tree.topLevelItemCount() > 0

    def test_analyze_installation_folder_searches_subdirectories(
        self, analysis_page: AnalysisPage, temp_installation_folder: Path
    ) -> None:
        """Installation folder analysis searches subdirectories recursively."""
        analysis_page.analyze_installation_folder(str(temp_installation_folder))
        licensing_files = analysis_page.get_licensing_files()

        file_paths = [f["path"] for f in licensing_files]
        subdoc_files = [p for p in file_paths if "docs" in p]
        assert subdoc_files

    def test_initialize_page_updates_program_info(
        self,
        analysis_page: AnalysisPage,
        program_selector_dialog: ProgramSelectorDialog,
        temp_exe_file: Path,
    ) -> None:
        """Initialize page updates program information display."""
        program_selector_dialog.selected_program = str(temp_exe_file)
        analysis_page.initializePage()

        info_text = analysis_page.program_info.text()
        assert "TestApp.exe" in info_text
        assert "Size:" in info_text

    def test_get_licensing_files_returns_list(self, analysis_page: AnalysisPage) -> None:
        """Get licensing files returns list of file metadata."""
        result = analysis_page.get_licensing_files()
        assert isinstance(result, list)

    def test_open_licensing_file_handles_invalid_item(
        self, analysis_page: AnalysisPage, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening licensing file with invalid item handles gracefully."""
        from PyQt6.QtWidgets import QTreeWidgetItem

        fake_msgbox = FakeMessageBox()
        FakeMessageBox._instance = fake_msgbox

        monkeypatch.setattr(QMessageBox, "warning", FakeMessageBox.warning)

        item = QTreeWidgetItem()
        analysis_page.open_licensing_file(item)

        FakeMessageBox._instance = None


class TestProgramSelectorDialogWorkflow:
    """Test complete program selection workflow."""

    def test_get_selected_program_returns_file_path(
        self, program_selector_dialog: ProgramSelectorDialog, temp_exe_file: Path
    ) -> None:
        """Get selected program returns file path from selection page."""
        program_selector_dialog.file_selection_page.file_path_edit.setText(str(temp_exe_file))
        result = program_selector_dialog.get_selected_program()
        assert result == str(temp_exe_file)

    def test_get_selected_program_data_includes_program_info(
        self, program_selector_dialog: ProgramSelectorDialog, temp_exe_file: Path
    ) -> None:
        """Get selected program data includes program information."""
        program_selector_dialog.file_selection_page.file_path_edit.setText(str(temp_exe_file))
        data = program_selector_dialog.get_selected_program_data()

        assert data is not None
        assert "program_info" in data
        assert "name" in data["program_info"]
        assert "path" in data["program_info"]

    def test_get_selected_program_data_includes_installation_folder(
        self, program_selector_dialog: ProgramSelectorDialog, temp_exe_file: Path
    ) -> None:
        """Get selected program data includes installation folder path."""
        program_selector_dialog.file_selection_page.file_path_edit.setText(str(temp_exe_file))
        data = program_selector_dialog.get_selected_program_data()

        assert data is not None
        assert "installation_folder" in data
        assert data["installation_folder"] == str(temp_exe_file.parent)

    def test_get_selected_program_data_includes_licensing_files(
        self,
        program_selector_dialog: ProgramSelectorDialog,
        temp_installation_folder: Path,
        temp_exe_file: Path,
    ) -> None:
        """Get selected program data includes discovered licensing files."""
        program_selector_dialog.file_selection_page.file_path_edit.setText(str(temp_exe_file))
        program_selector_dialog.selected_program = str(temp_exe_file)
        program_selector_dialog.analysis_page.initializePage()

        data = program_selector_dialog.get_selected_program_data()

        assert data is not None
        assert "licensing_files" in data
        assert isinstance(data["licensing_files"], list)

    def test_get_selected_program_data_sets_auto_analyze_flag(
        self, program_selector_dialog: ProgramSelectorDialog, temp_exe_file: Path
    ) -> None:
        """Get selected program data sets auto_analyze flag."""
        program_selector_dialog.file_selection_page.file_path_edit.setText(str(temp_exe_file))
        data = program_selector_dialog.get_selected_program_data()

        assert data is not None
        assert "auto_analyze" in data
        assert data["auto_analyze"] is True

    def test_get_selected_program_data_returns_none_without_selection(
        self, program_selector_dialog: ProgramSelectorDialog
    ) -> None:
        """Get selected program data returns None when no program selected."""
        data = program_selector_dialog.get_selected_program_data()
        assert data is None


class TestProgramSelectorConvenienceFunctions:
    """Test convenience functions for showing dialog."""

    def test_show_program_selector_returns_data_on_accept(
        self, qapp: QApplication, temp_exe_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Show program selector returns data when dialog is accepted."""
        fake_dialog = FakeProgramSelectorDialog()
        fake_dialog.set_exec_return_value(1)
        fake_dialog.set_program_data(
            {"program_info": {"name": "test.exe", "path": str(temp_exe_file)}}
        )

        original_init = ProgramSelectorDialog.__init__

        def fake_init(self: ProgramSelectorDialog) -> None:
            self.exec = fake_dialog.exec
            self.get_selected_program_data = fake_dialog.get_selected_program_data

        monkeypatch.setattr(ProgramSelectorDialog, "__init__", fake_init)

        result = show_program_selector()
        assert result is not None
        assert "program_info" in result
        assert fake_dialog.exec_calls == 1
        assert fake_dialog.get_selected_program_data_calls == 1

    def test_show_program_selector_returns_none_on_cancel(
        self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Show program selector returns None when dialog is cancelled."""
        fake_dialog = FakeProgramSelectorDialog()
        fake_dialog.set_exec_return_value(0)

        def fake_init(self: ProgramSelectorDialog) -> None:
            self.exec = fake_dialog.exec
            self.get_selected_program_data = fake_dialog.get_selected_program_data

        monkeypatch.setattr(ProgramSelectorDialog, "__init__", fake_init)

        result = show_program_selector()
        assert result is None
        assert fake_dialog.exec_calls == 1
        assert fake_dialog.get_selected_program_data_calls == 0


class TestAnalysisPageLicensingFileDetection:
    """Test comprehensive licensing file detection patterns."""

    def test_detects_license_file_with_various_extensions(
        self, analysis_page: AnalysisPage, tmp_path: Path
    ) -> None:
        """Analysis detects license files with different extensions."""
        test_files = ["license.txt", "LICENSE.md", "License.rst", "LICENCE"]
        for filename in test_files:
            (tmp_path / filename).write_text("License content")

        analysis_page.analyze_installation_folder(str(tmp_path))
        licensing_files = analysis_page.get_licensing_files()

        assert len(licensing_files) >= len(test_files)

    def test_detects_readme_as_documentation(
        self, analysis_page: AnalysisPage, tmp_path: Path
    ) -> None:
        """Analysis detects README files as documentation type."""
        (tmp_path / "README.txt").write_text("Documentation")
        analysis_page.analyze_installation_folder(str(tmp_path))
        licensing_files = analysis_page.get_licensing_files()

        readme_files = [f for f in licensing_files if "README" in f["name"]]
        assert readme_files
        assert readme_files[0]["type"] == "Documentation"

    def test_assigns_correct_priority_to_license(
        self, analysis_page: AnalysisPage, tmp_path: Path
    ) -> None:
        """Analysis assigns priority 1 to license files."""
        (tmp_path / "LICENSE").write_text("License text")
        analysis_page.analyze_installation_folder(str(tmp_path))
        licensing_files = analysis_page.get_licensing_files()

        license_file = [f for f in licensing_files if "LICENSE" in f["name"]][0]
        assert license_file["priority"] == 1

    def test_handles_empty_directory_gracefully(
        self, analysis_page: AnalysisPage, tmp_path: Path
    ) -> None:
        """Analysis handles empty directories without errors."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        analysis_page.analyze_installation_folder(str(empty_dir))
        licensing_files = analysis_page.get_licensing_files()

        assert isinstance(licensing_files, list)
        assert len(licensing_files) == 0

    def test_handles_nonexistent_directory_gracefully(
        self, analysis_page: AnalysisPage
    ) -> None:
        """Analysis handles nonexistent directories without crashing."""
        analysis_page.analyze_installation_folder("/nonexistent/directory")
        licensing_files = analysis_page.get_licensing_files()
        assert isinstance(licensing_files, list)
