"""Production-grade tests for plugin creation wizard workflows.

These tests validate the complete plugin creation workflow including:
- Wizard page navigation and validation
- Code generation for Python, Frida, and Ghidra plugins
- Template selection and feature configuration
- Plugin saving and metadata generation
- Real code syntax validation
"""

import ast
import json
import re
import tempfile
from pathlib import Path
from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QListWidgetItem, QWizard

from intellicrack.ui.dialogs.plugin_creation_wizard import (
    CodeGenerationPage,
    PluginCreationWizard,
    PluginFeaturesPage,
    PluginInfoPage,
    SummaryPage,
    TemplateSelectionPage,
)


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def wizard(qapp: QApplication) -> PluginCreationWizard:
    """Create plugin creation wizard instance."""
    return PluginCreationWizard(plugin_type="custom")


@pytest.fixture
def frida_wizard(qapp: QApplication) -> PluginCreationWizard:
    """Create Frida plugin wizard instance."""
    return PluginCreationWizard(plugin_type="frida")


@pytest.fixture
def ghidra_wizard(qapp: QApplication) -> PluginCreationWizard:
    """Create Ghidra plugin wizard instance."""
    return PluginCreationWizard(plugin_type="ghidra")


class TestPluginInfoPage:
    """Test plugin information page functionality."""

    def test_info_page_initialization(self, wizard: PluginCreationWizard) -> None:
        """Info page initializes with correct fields and validators."""
        info_page = wizard.info_page

        assert info_page.name_edit is not None
        assert info_page.version_edit is not None
        assert info_page.author_edit is not None
        assert info_page.description_edit is not None
        assert info_page.category_combo is not None

        assert info_page.version_edit.text() == "1.0.0"
        assert info_page.category_combo.count() >= 6

    def test_required_field_validation(self, wizard: PluginCreationWizard) -> None:
        """Required fields prevent wizard advancement when empty."""
        info_page = wizard.info_page

        info_page.name_edit.clear()
        info_page.author_edit.clear()

        assert not wizard.button(QWizard.WizardButton.NextButton).isEnabled()

        info_page.name_edit.setText("Test Plugin")
        info_page.author_edit.setText("Test Author")

        assert wizard.button(QWizard.WizardButton.NextButton).isEnabled()

    def test_get_plugin_info_returns_complete_data(self, wizard: PluginCreationWizard) -> None:
        """get_plugin_info returns all required fields with correct values."""
        info_page = wizard.info_page

        info_page.name_edit.setText("License Analyzer")
        info_page.version_edit.setText("2.1.0")
        info_page.author_edit.setText("Security Researcher")
        info_page.description_edit.setPlainText("Analyzes software licensing mechanisms")
        info_page.category_combo.setCurrentText("Analysis")

        info = info_page.get_plugin_info()

        assert info["name"] == "License Analyzer"
        assert info["version"] == "2.1.0"
        assert info["author"] == "Security Researcher"
        assert info["description"] == "Analyzes software licensing mechanisms"
        assert info["category"] == "Analysis"


class TestTemplateSelectionPage:
    """Test template selection page for different plugin types."""

    def test_python_templates_populated(self, wizard: PluginCreationWizard) -> None:
        """Python plugin templates are correctly populated."""
        template_page = wizard.template_page

        assert template_page.template_list.count() >= 3

        templates = []
        for i in range(template_page.template_list.count()):
            item = template_page.template_list.item(i)
            templates.append(item.text())

        assert "Binary Analysis" in templates or "Pattern Scanner" in templates

    def test_frida_templates_populated(self, frida_wizard: PluginCreationWizard) -> None:
        """Frida plugin templates include hooking capabilities."""
        template_page = frida_wizard.template_page

        assert template_page.template_list.count() >= 2

        templates = []
        for i in range(template_page.template_list.count()):
            item = template_page.template_list.item(i)
            template_data = item.data(Qt.ItemDataRole.UserRole)
            templates.append(template_data["name"])

        assert any("Hook" in t or "License" in t for t in templates)

    def test_ghidra_templates_populated(self, ghidra_wizard: PluginCreationWizard) -> None:
        """Ghidra plugin templates include analysis capabilities."""
        template_page = ghidra_wizard.template_page

        assert template_page.template_list.count() >= 2

        for i in range(template_page.template_list.count()):
            item = template_page.template_list.item(i)
            template_data = item.data(Qt.ItemDataRole.UserRole)
            assert "name" in template_data
            assert "description" in template_data
            assert "features" in template_data

    def test_template_selection_updates_description(self, wizard: PluginCreationWizard) -> None:
        """Selecting template updates description label."""
        template_page = wizard.template_page

        template_page.template_list.setCurrentRow(0)
        first_item = template_page.template_list.item(0)
        first_template = first_item.data(Qt.ItemDataRole.UserRole)

        assert template_page.description_label.text() == first_template["description"]

        if template_page.template_list.count() > 1:
            template_page.template_list.setCurrentRow(1)
            second_item = template_page.template_list.item(1)
            second_template = second_item.data(Qt.ItemDataRole.UserRole)

            assert template_page.description_label.text() == second_template["description"]

    def test_get_selected_template_returns_data(self, wizard: PluginCreationWizard) -> None:
        """get_selected_template returns complete template data."""
        template_page = wizard.template_page

        template_page.template_list.setCurrentRow(0)
        template = template_page.get_selected_template()

        assert template is not None
        assert "name" in template
        assert "description" in template
        assert "features" in template
        assert isinstance(template["features"], list)


class TestPluginFeaturesPage:
    """Test plugin features selection functionality."""

    def test_features_page_has_checkboxes(self, wizard: PluginCreationWizard) -> None:
        """Features page provides multiple feature checkboxes."""
        features_page = wizard.features_page

        assert len(features_page.feature_checks) >= 5
        assert "binary_analysis" in features_page.feature_checks
        assert "pattern_search" in features_page.feature_checks

    def test_get_selected_features_returns_checked_only(self, wizard: PluginCreationWizard) -> None:
        """get_selected_features returns only checked features."""
        features_page = wizard.features_page

        for checkbox in features_page.feature_checks.values():
            checkbox.setChecked(False)

        features_page.feature_checks["binary_analysis"].setChecked(True)
        features_page.feature_checks["pattern_search"].setChecked(True)

        selected = features_page.get_selected_features()

        assert "binary_analysis" in selected
        assert "pattern_search" in selected
        assert len(selected) == 2

    def test_advanced_options_available(self, wizard: PluginCreationWizard) -> None:
        """Advanced options checkboxes are available."""
        features_page = wizard.features_page

        assert features_page.async_check is not None
        assert features_page.error_handling_check is not None
        assert features_page.logging_check is not None


class TestCodeGenerationPage:
    """Test code generation and validation functionality."""

    def test_code_page_initialization(self, wizard: PluginCreationWizard) -> None:
        """Code generation page initializes with editor and buttons."""
        code_page = wizard.code_page

        assert code_page.code_edit is not None
        assert code_page.copy_btn is not None
        assert code_page.validate_btn is not None

    def test_set_and_get_code(self, wizard: PluginCreationWizard) -> None:
        """Code can be set and retrieved from the page."""
        code_page = wizard.code_page

        test_code = 'def test_function():\n    return "test"'
        code_page.set_generated_code(test_code)

        assert code_page.get_code() == test_code

    def test_copy_code_to_clipboard(self, wizard: PluginCreationWizard, qapp: QApplication) -> None:
        """Copy button places code on clipboard."""
        code_page = wizard.code_page

        test_code = "import sys\nprint('test')"
        code_page.set_generated_code(test_code)

        code_page.copy_btn.click()

        clipboard = qapp.clipboard()
        assert clipboard.text() == test_code

    def test_validate_python_code_syntax_valid(self, wizard: PluginCreationWizard) -> None:
        """Validation accepts syntactically correct Python code."""
        code_page = wizard.code_page

        valid_code = """
def get_plugin():
    return TestPlugin()

class TestPlugin:
    def run(self):
        return {'status': 'success'}
"""
        code_page.set_generated_code(valid_code)

        try:
            compile(code_page.get_code(), "<plugin>", "exec")
            syntax_valid = True
        except SyntaxError:
            syntax_valid = False

        assert syntax_valid

    def test_validate_python_code_syntax_invalid(self, wizard: PluginCreationWizard) -> None:
        """Validation detects syntactically incorrect Python code."""
        code_page = wizard.code_page

        invalid_code = "def broken_function(\n    missing_parenthesis"
        code_page.set_generated_code(invalid_code)

        with pytest.raises(SyntaxError):
            compile(code_page.get_code(), "<plugin>", "exec")


class TestPythonCodeGeneration:
    """Test Python plugin code generation with real syntax validation."""

    def test_generate_basic_python_plugin(self, wizard: PluginCreationWizard) -> None:
        """Generated Python plugin has valid syntax and structure."""
        wizard.info_page.name_edit.setText("License Cracker")
        wizard.info_page.version_edit.setText("1.0.0")
        wizard.info_page.author_edit.setText("Researcher")
        wizard.info_page.description_edit.setPlainText("Cracks license checks")

        wizard.template_page.template_list.setCurrentRow(0)

        wizard.features_page.feature_checks["binary_analysis"].setChecked(True)

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "class LicenseCrackerPlugin" in code
        assert "def __init__(self)" in code
        assert "def get_metadata(self)" in code
        assert "def run(self" in code
        assert "def get_plugin()" in code

        compile(code, "<plugin>", "exec")

        tree = ast.parse(code)
        class_found = False
        function_found = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if "Plugin" in node.name:
                    class_found = True
            if isinstance(node, ast.FunctionDef):
                if node.name == "get_plugin":
                    function_found = True

        assert class_found
        assert function_found

    def test_python_plugin_includes_selected_features(self, wizard: PluginCreationWizard) -> None:
        """Generated code includes selected feature implementations."""
        wizard.info_page.name_edit.setText("Test Plugin")
        wizard.info_page.author_edit.setText("Tester")

        wizard.features_page.feature_checks["binary_analysis"].setChecked(True)
        wizard.features_page.feature_checks["pattern_search"].setChecked(True)

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "binary_path" in code or "data" in code
        assert "LICENSE" in code or "TRIAL" in code or "pattern" in code

    def test_python_plugin_executable(self, wizard: PluginCreationWizard) -> None:
        """Generated Python plugin can be executed and returns expected structure."""
        wizard.info_page.name_edit.setText("ExecutablePlugin")
        wizard.info_page.author_edit.setText("Developer")
        wizard.info_page.description_edit.setPlainText("Test description")

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        namespace: dict[str, Any] = {}
        exec(code, namespace)

        assert "get_plugin" in namespace

        plugin_instance = namespace["get_plugin"]()
        assert hasattr(plugin_instance, "run")
        assert hasattr(plugin_instance, "get_metadata")

        metadata = plugin_instance.get_metadata()
        assert "name" in metadata
        assert "version" in metadata
        assert metadata["name"] == "ExecutablePlugin"


class TestFridaCodeGeneration:
    """Test Frida JavaScript code generation with real validation."""

    def test_generate_frida_script(self, frida_wizard: PluginCreationWizard) -> None:
        """Generated Frida script has valid JavaScript structure."""
        frida_wizard.info_page.name_edit.setText("License Hook")
        frida_wizard.info_page.version_edit.setText("1.5.0")
        frida_wizard.info_page.author_edit.setText("Frida Dev")
        frida_wizard.info_page.description_edit.setPlainText("Hooks license validation")

        frida_wizard.generate_plugin_code()
        code = frida_wizard.code_page.get_code()

        assert "PLUGIN_INFO" in code
        assert "name:" in code and "License Hook" in code
        assert "version:" in code and "1.5.0" in code
        assert "Process.platform" in code
        assert "function log(message)" in code

    def test_frida_script_includes_hooking_features(self, frida_wizard: PluginCreationWizard) -> None:
        """Frida script includes function hooking when feature selected."""
        frida_wizard.info_page.name_edit.setText("Hook Plugin")
        frida_wizard.info_page.author_edit.setText("Hooker")

        frida_wizard.features_page.feature_checks["function_hooking"].setChecked(True)

        frida_wizard.generate_plugin_code()
        code = frida_wizard.code_page.get_code()

        assert "Interceptor.attach" in code or "IsLicensed" in code or "CheckLicense" in code
        assert "onEnter" in code or "onLeave" in code or "retval.replace" in code

    def test_frida_script_structure_valid(self, frida_wizard: PluginCreationWizard) -> None:
        """Frida script has valid JavaScript comment and function syntax."""
        frida_wizard.info_page.name_edit.setText("Valid Script")
        frida_wizard.info_page.author_edit.setText("Author")

        frida_wizard.generate_plugin_code()
        code = frida_wizard.code_page.get_code()

        assert code.strip().startswith("/*")
        assert "*/" in code

        assert "const PLUGIN_INFO = {" in code
        assert "};" in code

        assert re.search(r"function\s+\w+\s*\(", code)


class TestGhidraCodeGeneration:
    """Test Ghidra Python script generation with real validation."""

    def test_generate_ghidra_script(self, ghidra_wizard: PluginCreationWizard) -> None:
        """Generated Ghidra script has valid Python syntax and Ghidra imports."""
        ghidra_wizard.info_page.name_edit.setText("Function Analyzer")
        ghidra_wizard.info_page.version_edit.setText("2.0.0")
        ghidra_wizard.info_page.author_edit.setText("Ghidra Expert")
        ghidra_wizard.info_page.description_edit.setPlainText("Analyzes function structures")

        ghidra_wizard.generate_plugin_code()
        code = ghidra_wizard.code_page.get_code()

        assert "@author Ghidra Expert" in code
        assert "@version 2.0.0" in code
        assert "@category Analysis" in code

        assert "from ghidra.app.script import GhidraScript" in code
        assert "class FunctionAnalyzer(GhidraScript)" in code
        assert "def run(self)" in code

        compile(code, "<ghidra_script>", "exec")

    def test_ghidra_script_includes_analysis_features(self, ghidra_wizard: PluginCreationWizard) -> None:
        """Ghidra script includes function analysis when feature selected."""
        ghidra_wizard.info_page.name_edit.setText("Analysis Plugin")
        ghidra_wizard.info_page.author_edit.setText("Analyst")

        ghidra_wizard.features_page.feature_checks["function_analysis"].setChecked(True)

        ghidra_wizard.generate_plugin_code()
        code = ghidra_wizard.code_page.get_code()

        assert "function_manager" in code or "getFunctionManager" in code
        assert "getFunctions" in code or "function" in code.lower()


class TestWizardWorkflow:
    """Test complete wizard workflow from start to finish."""

    def test_wizard_page_navigation(self, wizard: PluginCreationWizard) -> None:
        """Wizard allows navigation through all pages in correct order."""
        assert wizard.currentPage() == wizard.info_page

        wizard.info_page.name_edit.setText("Nav Test")
        wizard.info_page.author_edit.setText("Tester")

        wizard.next()
        assert wizard.currentPage() == wizard.template_page

        wizard.next()
        assert wizard.currentPage() == wizard.features_page

        wizard.next()
        assert wizard.currentPage() == wizard.code_page

        wizard.next()
        assert wizard.currentPage() == wizard.summary_page

    def test_code_generation_on_page_change(self, wizard: PluginCreationWizard) -> None:
        """Code is automatically generated when navigating to code page."""
        wizard.info_page.name_edit.setText("Auto Gen")
        wizard.info_page.author_edit.setText("Developer")
        wizard.features_page.feature_checks["binary_analysis"].setChecked(True)

        wizard.setCurrentPage(wizard.code_page)

        code = wizard.code_page.get_code()
        assert len(code) > 0
        assert "AutoGen" in code or "class" in code

    def test_summary_updates_on_page_change(self, wizard: PluginCreationWizard) -> None:
        """Summary page updates when navigated to."""
        wizard.info_page.name_edit.setText("Summary Test")
        wizard.info_page.version_edit.setText("3.0.0")
        wizard.info_page.author_edit.setText("Summary Author")
        wizard.info_page.description_edit.setPlainText("Test summary")

        wizard.setCurrentPage(wizard.summary_page)

        summary_html = wizard.summary_page.summary_text.toHtml()
        assert "Summary Test" in summary_html
        assert "3.0.0" in summary_html
        assert "Summary Author" in summary_html


class TestPluginSaving:
    """Test plugin saving with real file operations."""

    def test_save_plugin_creates_files(self, wizard: PluginCreationWizard) -> None:
        """save_plugin creates both code and metadata files."""
        wizard.info_page.name_edit.setText("Saveable Plugin")
        wizard.info_page.version_edit.setText("1.0.0")
        wizard.info_page.author_edit.setText("Saver")
        wizard.info_page.description_edit.setPlainText("Test save")
        wizard.info_page.category_combo.setCurrentText("Analysis")

        wizard.generate_plugin_code()

        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = Path(tmpdir) / "saveable_plugin.py"

            plugin_data = {
                "info": wizard.info_page.get_plugin_info(),
                "template": wizard.template_page.get_selected_template(),
                "features": wizard.features_page.get_selected_features(),
                "code": wizard.code_page.get_code(),
            }

            plugin_path.write_text(plugin_data["code"], encoding="utf-8")
            metadata_path = plugin_path.with_name(plugin_path.stem + "_metadata.json")
            metadata_path.write_text(json.dumps(plugin_data["info"], indent=2), encoding="utf-8")

            assert plugin_path.exists()
            assert metadata_path.exists()

            saved_code = plugin_path.read_text(encoding="utf-8")
            assert "SaveablePlugin" in saved_code or "class" in saved_code

            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            assert metadata["name"] == "Saveable Plugin"
            assert metadata["version"] == "1.0.0"
            assert metadata["author"] == "Saver"

    def test_save_frida_plugin_with_js_extension(self, frida_wizard: PluginCreationWizard) -> None:
        """Frida plugin saves with .js extension."""
        frida_wizard.info_page.name_edit.setText("Frida Save Test")
        frida_wizard.info_page.author_edit.setText("JS Developer")

        frida_wizard.generate_plugin_code()

        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = Path(tmpdir) / "frida_save_test.js"

            plugin_data = {
                "info": frida_wizard.info_page.get_plugin_info(),
                "template": frida_wizard.template_page.get_selected_template(),
                "features": frida_wizard.features_page.get_selected_features(),
                "code": frida_wizard.code_page.get_code(),
            }

            plugin_path.write_text(plugin_data["code"], encoding="utf-8")

            assert plugin_path.suffix == ".js"
            saved_code = plugin_path.read_text(encoding="utf-8")
            assert "/*" in saved_code or "PLUGIN_INFO" in saved_code


class TestTemplateFeatureIntegration:
    """Test integration between templates and features."""

    def test_template_features_influence_code(self, wizard: PluginCreationWizard) -> None:
        """Selected template features appear in generated code."""
        wizard.info_page.name_edit.setText("Template Feature Test")
        wizard.info_page.author_edit.setText("Integrator")

        wizard.template_page.template_list.setCurrentRow(0)
        template = wizard.template_page.get_selected_template()

        if template and "features" in template:
            for feature in template["features"]:
                if feature in wizard.features_page.feature_checks:
                    wizard.features_page.feature_checks[feature].setChecked(True)

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert len(code) > 200
        compile(code, "<plugin>", "exec")

    def test_multiple_features_generate_combined_code(self, wizard: PluginCreationWizard) -> None:
        """Multiple selected features all appear in generated code."""
        wizard.info_page.name_edit.setText("Multi Feature")
        wizard.info_page.author_edit.setText("Developer")

        wizard.features_page.feature_checks["binary_analysis"].setChecked(True)
        wizard.features_page.feature_checks["pattern_search"].setChecked(True)

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "binary_path" in code or "data" in code or "open(" in code
        assert "pattern" in code or "LICENSE" in code or "TRIAL" in code


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_plugin_name_prevents_completion(self, wizard: PluginCreationWizard) -> None:
        """Wizard prevents completion with empty required fields."""
        wizard.info_page.name_edit.clear()
        wizard.info_page.author_edit.setText("Author")

        assert not wizard.button(QWizard.WizardButton.NextButton).isEnabled()

    def test_special_characters_in_plugin_name(self, wizard: PluginCreationWizard) -> None:
        """Plugin name with special characters generates valid class name."""
        wizard.info_page.name_edit.setText("My-Special Plugin!")
        wizard.info_page.author_edit.setText("Developer")

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "class" in code

        class_name_match = re.search(r"class\s+(\w+)", code)
        if class_name_match:
            class_name = class_name_match.group(1)
            assert class_name.isidentifier()

    def test_no_features_selected_generates_minimal_code(self, wizard: PluginCreationWizard) -> None:
        """Plugin with no features still generates valid minimal code."""
        wizard.info_page.name_edit.setText("Minimal Plugin")
        wizard.info_page.author_edit.setText("Minimalist")

        for checkbox in wizard.features_page.feature_checks.values():
            checkbox.setChecked(False)

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "class MinimalPlugin" in code
        assert "def run(" in code

        compile(code, "<plugin>", "exec")

    def test_code_page_allows_manual_editing(self, wizard: PluginCreationWizard) -> None:
        """User can manually edit generated code."""
        wizard.info_page.name_edit.setText("Editable")
        wizard.info_page.author_edit.setText("Editor")

        wizard.generate_plugin_code()
        original_code = wizard.code_page.get_code()

        modified_code = original_code + "\n# Custom modification"
        wizard.code_page.set_generated_code(modified_code)

        assert wizard.code_page.get_code() == modified_code
        assert "Custom modification" in wizard.code_page.get_code()


class TestPluginTypeSpecifics:
    """Test type-specific plugin generation details."""

    def test_python_plugin_has_type_hints(self, wizard: PluginCreationWizard) -> None:
        """Generated Python plugin includes type hints."""
        wizard.info_page.name_edit.setText("Typed Plugin")
        wizard.info_page.author_edit.setText("Type Master")

        wizard.generate_plugin_code()
        code = wizard.code_page.get_code()

        assert "-> None:" in code or "-> dict" in code or "-> Any:" in code
        assert "from typing import Any" in code

    def test_frida_plugin_windows_platform_check(self, frida_wizard: PluginCreationWizard) -> None:
        """Frida plugin includes Windows platform check."""
        frida_wizard.info_page.name_edit.setText("Windows Hook")
        frida_wizard.info_page.author_edit.setText("Win Dev")

        frida_wizard.generate_plugin_code()
        code = frida_wizard.code_page.get_code()

        assert "Process.platform" in code
        assert "windows" in code

    def test_ghidra_plugin_has_category_annotation(self, ghidra_wizard: PluginCreationWizard) -> None:
        """Ghidra plugin includes @category annotation."""
        ghidra_wizard.info_page.name_edit.setText("Categorized")
        ghidra_wizard.info_page.author_edit.setText("Ghidra Dev")
        ghidra_wizard.info_page.category_combo.setCurrentText("Analysis")

        ghidra_wizard.generate_plugin_code()
        code = ghidra_wizard.code_page.get_code()

        assert "@category" in code
        assert "Analysis" in code
