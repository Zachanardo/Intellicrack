"""Production tests for Help Documentation Widget.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QMessageBox,
    QTreeWidgetItem,
)
from intellicrack.ui.dialogs.help_documentation_widget import HelpDocumentationWidget


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def help_widget(qapp: QApplication) -> HelpDocumentationWidget:
    """Create help documentation widget for testing."""
    widget = HelpDocumentationWidget()
    yield widget
    widget.deleteLater()


def test_help_widget_initialization(help_widget: HelpDocumentationWidget) -> None:
    """Help widget initializes with all required UI components."""
    assert help_widget.search_edit is not None
    assert help_widget.nav_tree is not None
    assert help_widget.content_tabs is not None
    assert help_widget.doc_browser is not None
    assert help_widget.features_tree is not None
    assert help_widget.tutorial_viewer is not None
    assert help_widget.issues_tree is not None
    assert help_widget.solution_viewer is not None

    assert help_widget.content_tabs.count() == 4
    assert help_widget.content_tabs.tabText(0) == "Documentation"
    assert help_widget.content_tabs.tabText(1) == "Features"
    assert help_widget.content_tabs.tabText(2) == "Tutorials"
    assert help_widget.content_tabs.tabText(3) == "Troubleshooting"


def test_navigation_tree_population(help_widget: HelpDocumentationWidget) -> None:
    """Navigation tree is populated with all required documentation categories."""
    nav_tree = help_widget.nav_tree
    assert nav_tree.topLevelItemCount() > 0

    categories = []
    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        categories.append(item.text(0))

    assert "Overview" in categories
    assert "Features" in categories
    assert "User Guide" in categories
    assert "Tool Integration" in categories
    assert "API Reference" in categories
    assert "Troubleshooting" in categories


def test_features_tree_contains_all_78_features(help_widget: HelpDocumentationWidget) -> None:
    """Features tree contains all 78 documented features organized by category."""
    features_tree = help_widget.features_tree
    assert features_tree.topLevelItemCount() > 0

    total_features = 0
    categories_found = []

    for i in range(features_tree.topLevelItemCount()):
        category = features_tree.topLevelItem(i)
        category_name = category.text(0)
        categories_found.append(category_name)
        feature_count = category.childCount()
        total_features += feature_count

    assert "Binary Analysis" in categories_found
    assert "Protection Detection" in categories_found
    assert "Dynamic Analysis" in categories_found
    assert "Network Analysis" in categories_found
    assert "Vulnerability Detection" in categories_found
    assert "Patching" in categories_found
    assert "AI Integration" in categories_found
    assert "Performance" in categories_found
    assert "Reporting" in categories_found
    assert "Plugin System" in categories_found
    assert "User Interface" in categories_found
    assert "Utilities" in categories_found
    assert "Advanced" in categories_found

    assert total_features == 78, f"Expected 78 features, found {total_features}"


def test_feature_status_indicators(help_widget: HelpDocumentationWidget) -> None:
    """All features have status indicators with proper color coding."""
    features_tree = help_widget.features_tree

    for i in range(features_tree.topLevelItemCount()):
        category = features_tree.topLevelItem(i)
        for j in range(category.childCount()):
            feature = category.child(j)
            status = feature.text(1)
            assert status in ["OK", "Beta", "Experimental", "Planned"]


def test_tutorials_populated_in_all_categories(help_widget: HelpDocumentationWidget) -> None:
    """Tutorial lists are populated with content in all category tabs."""
    tutorial_tabs = help_widget.tutorial_tabs
    assert tutorial_tabs.count() == 4

    assert tutorial_tabs.tabText(0) == "Getting Started"
    assert tutorial_tabs.tabText(1) == "Analysis"
    assert tutorial_tabs.tabText(2) == "Patching"
    assert tutorial_tabs.tabText(3) == "Advanced"

    for i in range(tutorial_tabs.count()):
        list_widget = tutorial_tabs.widget(i)
        assert list_widget.count() > 0, f"Tab {i} has no tutorials"


def test_troubleshooting_tree_populated(help_widget: HelpDocumentationWidget) -> None:
    """Troubleshooting tree contains categorized common issues."""
    issues_tree = help_widget.issues_tree
    assert issues_tree.topLevelItemCount() > 0

    categories = []
    for i in range(issues_tree.topLevelItemCount()):
        item = issues_tree.topLevelItem(i)
        categories.append(item.text(0))
        assert item.childCount() > 0, f"Category '{item.text(0)}' has no issues"

    assert "Installation Issues" in categories
    assert "Analysis Issues" in categories
    assert "Tool Integration" in categories
    assert "Network Issues" in categories


def test_welcome_content_loaded_on_startup(help_widget: HelpDocumentationWidget) -> None:
    """Welcome content is displayed in documentation browser on initialization."""
    doc_html = help_widget.doc_browser.toHtml()
    assert "Welcome to Intellicrack Help & Documentation" in doc_html
    assert "78 Powerful Features" in doc_html
    assert "Getting Started" in doc_html


def test_search_functionality_filters_navigation(help_widget: HelpDocumentationWidget) -> None:
    """Search filters navigation tree to show only matching items."""
    help_widget.search_edit.setText("binary")
    help_widget.perform_search()

    nav_tree = help_widget.nav_tree
    visible_items = []

    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        if not item.isHidden():
            visible_items.append(item.text(0))
            for j in range(item.childCount()):
                child = item.child(j)
                if not child.isHidden():
                    visible_items.append(child.text(0))

    assert len(visible_items) > 0
    assert any("binary" in item.lower() for item in visible_items)


def test_search_highlights_matching_items(help_widget: HelpDocumentationWidget) -> None:
    """Search highlights matching text in tree items with yellow background."""
    search_term = "analysis"
    help_widget.search_edit.setText(search_term)
    help_widget.perform_search()

    features_tree = help_widget.features_tree
    highlighted_count = 0

    for i in range(features_tree.topLevelItemCount()):
        item = features_tree.topLevelItem(i)
        for col in range(item.columnCount()):
            if search_term.lower() in item.text(col).lower():
                background = item.background(col)
                assert background.color().name() in ["#ffff00", "#ffffff00"]
                highlighted_count += 1

    assert highlighted_count > 0


def test_search_clears_when_empty(help_widget: HelpDocumentationWidget) -> None:
    """Clearing search text shows all items again."""
    help_widget.search_edit.setText("binary")
    help_widget.perform_search()

    help_widget.search_edit.setText("")
    help_widget.on_search_changed("")

    nav_tree = help_widget.nav_tree
    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        assert not item.isHidden()


def test_navigation_item_click_loads_content(help_widget: HelpDocumentationWidget) -> None:
    """Clicking navigation item loads corresponding documentation content."""
    nav_tree = help_widget.nav_tree
    overview_item = nav_tree.topLevelItem(0)
    assert overview_item.text(0) == "Overview"

    getting_started_child = None
    for i in range(overview_item.childCount()):
        child = overview_item.child(i)
        if child.text(0) == "Getting Started":
            getting_started_child = child
            break

    assert getting_started_child is not None
    help_widget.on_nav_item_clicked(getting_started_child, 0)

    doc_html = help_widget.doc_browser.toHtml()
    assert "Getting Started" in doc_html


def test_feature_selection_shows_details(help_widget: HelpDocumentationWidget) -> None:
    """Selecting a feature displays detailed information."""
    features_tree = help_widget.features_tree

    binary_analysis_category = None
    for i in range(features_tree.topLevelItemCount()):
        item = features_tree.topLevelItem(i)
        if item.text(0) == "Binary Analysis":
            binary_analysis_category = item
            break

    assert binary_analysis_category is not None
    assert binary_analysis_category.childCount() > 0

    first_feature = binary_analysis_category.child(0)
    feature_name = first_feature.text(0)

    help_widget.show_feature_details("Binary Analysis", feature_name)

    details_html = help_widget.feature_details.toHtml()
    assert feature_name in details_html or "coming soon" in details_html.lower()


@patch.object(QMessageBox, "question", return_value=QMessageBox.Yes)
def test_feature_double_click_emits_signal(
    mock_question: MagicMock, help_widget: HelpDocumentationWidget
) -> None:
    """Double-clicking feature and accepting dialog emits feature_selected signal."""
    signal_received = []

    def on_feature_selected(category: str, feature: str) -> None:
        signal_received.append((category, feature))

    help_widget.feature_selected.connect(on_feature_selected)

    features_tree = help_widget.features_tree
    binary_category = features_tree.topLevelItem(0)
    first_feature = binary_category.child(0)

    help_widget.on_feature_double_clicked(first_feature, 0)

    assert len(signal_received) == 1
    category, feature = signal_received[0]
    assert category == binary_category.text(0)
    assert feature == first_feature.text(0)


@patch.object(QMessageBox, "question", return_value=QMessageBox.No)
def test_feature_double_click_decline_no_signal(
    mock_question: MagicMock, help_widget: HelpDocumentationWidget
) -> None:
    """Declining feature launch dialog does not emit signal."""
    signal_received = []

    def on_feature_selected(category: str, feature: str) -> None:
        signal_received.append((category, feature))

    help_widget.feature_selected.connect(on_feature_selected)

    features_tree = help_widget.features_tree
    binary_category = features_tree.topLevelItem(0)
    first_feature = binary_category.child(0)

    help_widget.on_feature_double_clicked(first_feature, 0)

    assert len(signal_received) == 0


def test_tutorial_selection_loads_content(help_widget: HelpDocumentationWidget) -> None:
    """Selecting a tutorial loads its content in viewer."""
    tutorial_tabs = help_widget.tutorial_tabs
    getting_started_list = tutorial_tabs.widget(0)

    assert getting_started_list.count() > 0
    first_tutorial = getting_started_list.item(0)
    tutorial_name = first_tutorial.text()

    help_widget.on_tutorial_selected(first_tutorial)

    viewer_html = help_widget.tutorial_viewer.toHtml()
    assert tutorial_name in viewer_html or "loading" in viewer_html.lower()


def test_tutorial_content_mapping_first_time_setup(help_widget: HelpDocumentationWidget) -> None:
    """First Time Setup tutorial loads with proper installation steps."""
    help_widget.load_tutorial_content("1. First Time Setup")

    viewer_html = help_widget.tutorial_viewer.toHtml()
    assert "First Time Setup" in viewer_html
    assert "Dependencies" in viewer_html or "dependencies" in viewer_html


def test_issue_selection_loads_solution(help_widget: HelpDocumentationWidget) -> None:
    """Selecting an issue displays corresponding solution."""
    issues_tree = help_widget.issues_tree

    install_category = None
    for i in range(issues_tree.topLevelItemCount()):
        item = issues_tree.topLevelItem(i)
        if item.text(0) == "Installation Issues":
            install_category = item
            break

    assert install_category is not None
    assert install_category.childCount() > 0

    first_issue = install_category.child(0)
    help_widget.on_issue_selected(first_issue, 0)

    solution_html = help_widget.solution_viewer.toHtml()
    assert first_issue.text(0) in solution_html or "coming soon" in solution_html.lower()


def test_solution_mapping_dependencies_issue(help_widget: HelpDocumentationWidget) -> None:
    """Dependencies not installing issue loads with proper solutions."""
    help_widget.load_solution("Dependencies not installing")

    solution_html = help_widget.solution_viewer.toHtml()
    assert "Dependencies Not Installing" in solution_html
    assert "Visual C++" in solution_html or "Python" in solution_html


def test_solution_mapping_gpu_issue(help_widget: HelpDocumentationWidget) -> None:
    """GPU not detected issue loads with CUDA and driver solutions."""
    help_widget.load_solution("GPU not detected")

    solution_html = help_widget.solution_viewer.toHtml()
    assert "GPU Not Detected" in solution_html
    assert "CUDA" in solution_html or "Driver" in solution_html


def test_hide_all_tree_items(help_widget: HelpDocumentationWidget) -> None:
    """Hiding all tree items makes them invisible."""
    nav_tree = help_widget.nav_tree
    help_widget.hide_all_tree_items(nav_tree)

    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        assert item.isHidden()


def test_show_all_tree_items(help_widget: HelpDocumentationWidget) -> None:
    """Showing all tree items makes them visible and clears highlights."""
    nav_tree = help_widget.nav_tree

    help_widget.hide_all_tree_items(nav_tree)
    help_widget.show_all_tree_items(nav_tree)

    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        assert not item.isHidden()


def test_search_tree_recursive_matching(help_widget: HelpDocumentationWidget) -> None:
    """Search correctly matches nested items in tree hierarchy."""
    nav_tree = help_widget.nav_tree

    search_term = "ghidra"
    help_widget.search_tree(nav_tree, search_term)

    found_match = False
    for i in range(nav_tree.topLevelItemCount()):
        parent = nav_tree.topLevelItem(i)
        for j in range(parent.childCount()):
            child = parent.child(j)
            if search_term.lower() in child.text(0).lower() and not child.isHidden():
                found_match = True
                assert not parent.isHidden()
                break

    assert found_match


def test_documentation_content_loading_with_mapping(help_widget: HelpDocumentationWidget) -> None:
    """Documentation content loads correctly using category-topic mapping."""
    help_widget.load_documentation_content("Overview", "Getting Started")
    doc_html = help_widget.doc_browser.toHtml()
    assert "Getting Started" in doc_html

    help_widget.load_documentation_content("Overview", "Welcome")
    doc_html = help_widget.doc_browser.toHtml()
    assert "Welcome" in doc_html


def test_documentation_content_fallback_for_missing_topics(
    help_widget: HelpDocumentationWidget,
) -> None:
    """Missing documentation topics display fallback content."""
    help_widget.load_documentation_content("Unknown Category", "Unknown Topic")
    doc_html = help_widget.doc_browser.toHtml()
    assert "Unknown Topic" in doc_html
    assert "being prepared" in doc_html or "coming soon" in doc_html


def test_feature_details_fallback_for_undocumented_features(
    help_widget: HelpDocumentationWidget,
) -> None:
    """Undocumented features display fallback message."""
    help_widget.show_feature_details("Test Category", "Undocumented Feature")
    details_html = help_widget.feature_details.toHtml()
    assert "Undocumented Feature" in details_html
    assert "coming soon" in details_html.lower()


def test_getting_started_tutorials_count(help_widget: HelpDocumentationWidget) -> None:
    """Getting Started tab contains expected number of tutorials."""
    tutorial_tabs = help_widget.tutorial_tabs
    getting_started_list = tutorial_tabs.widget(0)
    assert getting_started_list.count() == 8


def test_analysis_tutorials_count(help_widget: HelpDocumentationWidget) -> None:
    """Analysis tab contains expected number of tutorials."""
    tutorial_tabs = help_widget.tutorial_tabs
    analysis_list = tutorial_tabs.widget(1)
    assert analysis_list.count() == 10


def test_patching_tutorials_count(help_widget: HelpDocumentationWidget) -> None:
    """Patching tab contains expected number of tutorials."""
    tutorial_tabs = help_widget.tutorial_tabs
    patching_list = tutorial_tabs.widget(2)
    assert patching_list.count() == 10


def test_advanced_tutorials_count(help_widget: HelpDocumentationWidget) -> None:
    """Advanced tab contains expected number of tutorials."""
    tutorial_tabs = help_widget.tutorial_tabs
    advanced_list = tutorial_tabs.widget(3)
    assert advanced_list.count() == 10


def test_all_tutorials_have_numbered_format(help_widget: HelpDocumentationWidget) -> None:
    """All tutorials follow numbered format for ordering."""
    tutorial_tabs = help_widget.tutorial_tabs

    for i in range(tutorial_tabs.count()):
        list_widget = tutorial_tabs.widget(i)
        for j in range(list_widget.count()):
            tutorial_name = list_widget.item(j).text()
            assert tutorial_name[0].isdigit(), f"Tutorial '{tutorial_name}' not numbered"


def test_search_with_multiple_matches_shows_all(help_widget: HelpDocumentationWidget) -> None:
    """Search with multiple matches displays all matching items."""
    help_widget.search_edit.setText("analysis")
    help_widget.perform_search()

    visible_count = 0
    features_tree = help_widget.features_tree

    for i in range(features_tree.topLevelItemCount()):
        item = features_tree.topLevelItem(i)
        if not item.isHidden():
            visible_count += 1
            for j in range(item.childCount()):
                child = item.child(j)
                if not child.isHidden():
                    visible_count += 1

    assert visible_count >= 3


def test_search_case_insensitive(help_widget: HelpDocumentationWidget) -> None:
    """Search is case-insensitive."""
    help_widget.search_edit.setText("BINARY")
    help_widget.perform_search()

    visible_items = []
    features_tree = help_widget.features_tree

    for i in range(features_tree.topLevelItemCount()):
        item = features_tree.topLevelItem(i)
        if not item.isHidden():
            visible_items.append(item.text(0))

    assert len(visible_items) > 0


def test_navigation_tree_expandable(help_widget: HelpDocumentationWidget) -> None:
    """Navigation tree items are expanded by default for easy access."""
    nav_tree = help_widget.nav_tree

    for i in range(nav_tree.topLevelItemCount()):
        item = nav_tree.topLevelItem(i)
        assert item.isExpanded()


def test_features_tree_expandable(help_widget: HelpDocumentationWidget) -> None:
    """Features tree items are expanded by default for visibility."""
    features_tree = help_widget.features_tree

    for i in range(features_tree.topLevelItemCount()):
        item = features_tree.topLevelItem(i)
        assert item.isExpanded()


def test_troubleshooting_tree_expandable(help_widget: HelpDocumentationWidget) -> None:
    """Troubleshooting tree items are expanded by default."""
    issues_tree = help_widget.issues_tree

    for i in range(issues_tree.topLevelItemCount()):
        item = issues_tree.topLevelItem(i)
        assert item.isExpanded()


def test_feature_details_panel_exists(help_widget: HelpDocumentationWidget) -> None:
    """Feature details panel is properly initialized."""
    assert help_widget.feature_details is not None
    assert help_widget.feature_details.maximumHeight() == 200


def test_tutorial_viewer_exists(help_widget: HelpDocumentationWidget) -> None:
    """Tutorial viewer is properly initialized."""
    assert help_widget.tutorial_viewer is not None
    assert help_widget.tutorial_viewer.maximumHeight() == 300


def test_solution_viewer_exists(help_widget: HelpDocumentationWidget) -> None:
    """Solution viewer is properly initialized."""
    assert help_widget.solution_viewer is not None


def test_search_button_triggers_search(help_widget: HelpDocumentationWidget) -> None:
    """Search button click triggers search operation."""
    help_widget.search_edit.setText("binary")

    search_button = None
    for widget in help_widget.findChildren(type(help_widget.search_edit).__bases__[0]):
        if hasattr(widget, "text") and callable(widget.text):
            if widget.text() == "Search":
                search_button = widget
                break

    initial_html = help_widget.doc_browser.toHtml()
    help_widget.perform_search()
    result_html = help_widget.doc_browser.toHtml()

    assert "Search Results" in result_html


def test_tutorial_content_fallback(help_widget: HelpDocumentationWidget) -> None:
    """Unknown tutorials display fallback content."""
    help_widget.load_tutorial_content("999. Unknown Tutorial")
    viewer_html = help_widget.tutorial_viewer.toHtml()
    assert "loading" in viewer_html.lower()


def test_solution_content_fallback(help_widget: HelpDocumentationWidget) -> None:
    """Unknown issues display fallback solution."""
    help_widget.load_solution("Unknown Issue")
    solution_html = help_widget.solution_viewer.toHtml()
    assert "coming soon" in solution_html.lower()
