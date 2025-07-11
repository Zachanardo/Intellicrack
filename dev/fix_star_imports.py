#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Fix star imports by analyzing usage and converting to explicit imports.
"""

import ast
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Map of star import sources to their provided symbols
STAR_IMPORT_MODULES = {
    'ui.common_imports': {
        'Qt', 'QThread', 'QTimer', 'pyqtSignal', 'QPoint', 'QRect', 'QSize',
        'QColor', 'QFont', 'QFontMetrics', 'QIcon', 'QKeyEvent', 'QKeySequence',
        'QMouseEvent', 'QPainter', 'QPaintEvent', 'QPen', 'QPixmap', 'QResizeEvent',
        'QAbstractItemView', 'QAbstractScrollArea', 'QAction', 'QApplication',
        'QButtonGroup', 'QCheckBox', 'QComboBox', 'QDesktopWidget', 'QDialog',
        'QDialogButtonBox', 'QFileDialog', 'QFormLayout', 'QFrame', 'QGridLayout',
        'QGroupBox', 'QHBoxLayout', 'QHeaderView', 'QInputDialog', 'QLabel',
        'QLineEdit', 'QListWidget', 'QListWidgetItem', 'QMainWindow', 'QMenu',
        'QMessageBox', 'QPlainTextEdit', 'QProgressBar', 'QPushButton', 'QRadioButton',
        'QScrollArea', 'QSizePolicy', 'QSlider', 'QSpacerItem', 'QSpinBox',
        'QSplashScreen', 'QSplitter', 'QStatusBar', 'QTableWidget', 'QTableWidgetItem',
        'QTabWidget', 'QTextBrowser', 'QTextEdit', 'QToolBar', 'QTreeWidget',
        'QTreeWidgetItem', 'QVBoxLayout', 'QWidget', 'QWizard', 'QWizardPage',
        'PYQT5_AVAILABLE'
    },
    'common_imports': {  # Same as above but without module prefix
        'Qt', 'QThread', 'QTimer', 'pyqtSignal', 'QPoint', 'QRect', 'QSize',
        'QColor', 'QFont', 'QFontMetrics', 'QIcon', 'QKeyEvent', 'QKeySequence',
        'QMouseEvent', 'QPainter', 'QPaintEvent', 'QPen', 'QPixmap', 'QResizeEvent',
        'QAbstractItemView', 'QAbstractScrollArea', 'QAction', 'QApplication',
        'QButtonGroup', 'QCheckBox', 'QComboBox', 'QDesktopWidget', 'QDialog',
        'QDialogButtonBox', 'QFileDialog', 'QFormLayout', 'QFrame', 'QGridLayout',
        'QGroupBox', 'QHBoxLayout', 'QHeaderView', 'QInputDialog', 'QLabel',
        'QLineEdit', 'QListWidget', 'QListWidgetItem', 'QMainWindow', 'QMenu',
        'QMessageBox', 'QPlainTextEdit', 'QProgressBar', 'QPushButton', 'QRadioButton',
        'QScrollArea', 'QSizePolicy', 'QSlider', 'QSpacerItem', 'QSpinBox',
        'QSplashScreen', 'QSplitter', 'QStatusBar', 'QTableWidget', 'QTableWidgetItem',
        'QTabWidget', 'QTextBrowser', 'QTextEdit', 'QToolBar', 'QTreeWidget',
        'QTreeWidgetItem', 'QVBoxLayout', 'QWidget', 'QWizard', 'QWizardPage',
        'PYQT5_AVAILABLE'
    }
}


class UsageAnalyzer(ast.NodeVisitor):
    """Analyze which symbols are used from star imports."""

    def __init__(self, available_symbols: Set[str]):
        self.available_symbols = available_symbols
        self.used_symbols = set()
        self.in_import = False

    def visit_Name(self, node):
        """Check if a name is used."""
        if not self.in_import and node.id in self.available_symbols:
            self.used_symbols.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        """Check attribute access (e.g., Qt.AlignCenter)."""
        if isinstance(node.value, ast.Name) and node.value.id in self.available_symbols:
            self.used_symbols.add(node.value.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        """Skip import statements."""
        self.in_import = True
        self.generic_visit(node)
        self.in_import = False

    def visit_ImportFrom(self, node):
        """Skip import statements."""
        self.in_import = True
        self.generic_visit(node)
        self.in_import = False


def analyze_file(file_path: Path) -> Dict[str, Set[str]]:
    """Analyze a file to find which symbols are used from star imports."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    try:
        tree = ast.parse(content)
    except SyntaxError:
        print(f"Syntax error in {file_path}")
        return {}

    # Find star imports
    star_imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if any(alias.name == '*' for alias in node.names):
                module_name = node.module if node.module else ''
                if node.level > 0:
                    # Relative import
                    module_name = ('.' * node.level) + module_name

                # Map to known modules
                for known_module, symbols in STAR_IMPORT_MODULES.items():
                    if module_name.endswith(known_module):
                        star_imports[module_name] = symbols
                        break

    # Analyze usage
    results = {}
    for module, available_symbols in star_imports.items():
        analyzer = UsageAnalyzer(available_symbols)
        analyzer.visit(tree)
        results[module] = analyzer.used_symbols

    return results


def fix_star_import(file_path: Path, module: str, used_symbols: Set[str]) -> bool:
    """Replace star import with explicit imports."""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Find the star import line
    import_line_idx = None
    for i, line in enumerate(lines):
        if f"from {module} import *" in line:
            import_line_idx = i
            break

    if import_line_idx is None:
        return False

    # Generate explicit import
    if not used_symbols:
        # No symbols used, remove the import
        del lines[import_line_idx]
    else:
        # Sort symbols for consistent output
        sorted_symbols = sorted(used_symbols)

        # Format import based on length
        if len(sorted_symbols) <= 3:
            new_import = f"from {module} import {', '.join(sorted_symbols)}\n"
        else:
            # Multi-line import
            import_lines = [f"from {module} import (\n"]
            for i, symbol in enumerate(sorted_symbols):
                if i < len(sorted_symbols) - 1:
                    import_lines.append(f"    {symbol},\n")
                else:
                    import_lines.append(f"    {symbol}\n")
            import_lines.append(")\n")
            new_import = ''.join(import_lines)

        lines[import_line_idx] = new_import

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    return True


def main():
    """Main function to fix star imports."""
    # Files with star imports from common_imports
    files_to_fix = [
        "intellicrack/hexview/advanced_search.py",
        "intellicrack/hexview/data_inspector.py",
        "intellicrack/hexview/performance_monitor.py",
        "intellicrack/ui/dialogs/keygen_dialog.py",
        "intellicrack/ui/dialogs/script_generator_dialog.py"
    ]

    project_root = Path('..')

    for file_path in files_to_fix:
        full_path = project_root / file_path
        if not full_path.exists():
            print(f"File not found: {full_path}")
            continue

        print(f"\nAnalyzing {file_path}...")
        usage = analyze_file(full_path)

        for module, used_symbols in usage.items():
            if used_symbols:
                print(f"  Module: {module}")
                print(f"  Used symbols: {', '.join(sorted(used_symbols))}")

                if fix_star_import(full_path, module, used_symbols):
                    print(f"  ✓ Fixed star import")
                else:
                    print(f"  ✗ Failed to fix star import")
            else:
                print(f"  Module: {module} - No symbols used")


if __name__ == "__main__":
    main()
