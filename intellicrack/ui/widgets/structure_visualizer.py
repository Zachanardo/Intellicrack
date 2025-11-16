"""Structure Visualization Widget.

Provides interactive visualization for binary file structures (PE/ELF/Mach-O),
showing headers, sections, imports/exports, and other structural elements.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    import pyqtgraph as pg

    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False


class StructureVisualizerWidget(QWidget):
    """Interactive structure visualization widget for binary files."""

    # Signals
    #: section_name, section_data (type: str, dict)
    section_selected = pyqtSignal(str, dict)
    #: header_type, field_name, value (type: str, str, Any)
    header_field_selected = pyqtSignal(str, str, Any)

    def __init__(self, parent=None) -> None:
        """Initialize structure visualizer widget with binary structure analysis capabilities."""
        super().__init__(parent)
        self.current_binary = None
        self.structures = {}
        self.structure_data = {}
        self.binary_format = "Unknown"
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the UI components."""
        layout = QVBoxLayout(self)

        # Controls
        controls_layout = QHBoxLayout()

        controls_layout.addWidget(QLabel("View:"))
        self.view_combo = QComboBox()
        self.view_combo.addItems(
            [
                "Tree View",
                "Headers",
                "Sections",
                "Imports/Exports",
                "Resources",
                "Memory Map",
            ],
        )
        self.view_combo.currentTextChanged.connect(self.update_view)
        controls_layout.addWidget(self.view_combo)

        # Options
        self.show_raw_data_cb = QCheckBox("Show Raw Data")
        self.show_raw_data_cb.stateChanged.connect(self.update_view)
        controls_layout.addWidget(self.show_raw_data_cb)

        self.highlight_suspicious_cb = QCheckBox("Highlight Suspicious")
        self.highlight_suspicious_cb.setChecked(True)
        self.highlight_suspicious_cb.stateChanged.connect(self.update_view)
        controls_layout.addWidget(self.highlight_suspicious_cb)

        controls_layout.addStretch()

        # Export button
        self.export_btn = QPushButton("Export Structure")
        self.export_btn.clicked.connect(self.export_structure)
        controls_layout.addWidget(self.export_btn)

        layout.addLayout(controls_layout)

        # Main content area
        self.content_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Structure view
        self.structure_widget = QTabWidget()
        self.content_splitter.addWidget(self.structure_widget)

        # Right panel - Details
        details_group = QGroupBox("Details")
        details_layout = QVBoxLayout(details_group)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumWidth(400)
        details_layout.addWidget(self.details_text)

        self.content_splitter.addWidget(details_group)
        self.content_splitter.setSizes([700, 400])

        layout.addWidget(self.content_splitter)

        # Initialize views
        self._init_views()

    def _init_views(self) -> None:
        """Initialize the different view widgets."""
        # Tree view
        self.tree_view = QTreeWidget()
        self.tree_view.setHeaderLabel("Binary Structure")
        self.tree_view.itemSelectionChanged.connect(self._on_tree_selection)
        self.structure_widget.addTab(self.tree_view, "Tree")

        # Headers table
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(3)
        self.headers_table.setHorizontalHeaderLabels(["Field", "Value", "Description"])
        self.headers_table.horizontalHeader().setStretchLastSection(True)
        self.structure_widget.addTab(self.headers_table, "Headers")

        # Sections table
        self.sections_table = QTableWidget()
        self.sections_table.setColumnCount(6)
        self.sections_table.setHorizontalHeaderLabels(
            [
                "Name",
                "Virtual Addr",
                "Virtual Size",
                "Raw Addr",
                "Raw Size",
                "Characteristics",
            ],
        )
        self.sections_table.itemSelectionChanged.connect(self._on_section_selection)
        self.structure_widget.addTab(self.sections_table, "Sections")

        # Imports/Exports
        self.imports_widget = QTabWidget()

        # Imports table
        self.imports_table = QTableWidget()
        self.imports_table.setColumnCount(3)
        self.imports_table.setHorizontalHeaderLabels(["DLL", "Function", "Ordinal"])
        self.imports_widget.addTab(self.imports_table, "Imports")

        # Exports table
        self.exports_table = QTableWidget()
        self.exports_table.setColumnCount(4)
        self.exports_table.setHorizontalHeaderLabels(["Ordinal", "Name", "Address", "Forwarded"])
        self.imports_widget.addTab(self.exports_table, "Exports")

        self.structure_widget.addTab(self.imports_widget, "Imports/Exports")

        # Memory map visualization
        if PYQTGRAPH_AVAILABLE:
            self.memory_map = pg.PlotWidget()
            self.memory_map.setLabel("left", "Section")
            self.memory_map.setLabel("bottom", "Memory Address")
            self.structure_widget.addTab(self.memory_map, "Memory Map")

    def set_structure_data(self, data: dict[str, Any]) -> None:
        """Set structure data for visualization."""
        self.structure_data = data
        self.binary_format = data.get("format", "Unknown")

        # Update all views
        self.update_view()
        self.update_details()

    def load_structure(self, data: dict[str, Any]) -> None:
        """Load structure data for visualization (alias for set_structure_data)."""
        self.set_structure_data(data)

    def update_view(self) -> None:
        """Update the current view."""
        if not self.structure_data:
            return

        current_view = self.view_combo.currentText()

        if current_view == "Tree View":
            self._update_tree_view()
            self.structure_widget.setCurrentIndex(0)
        elif current_view == "Headers":
            self._update_headers_view()
            self.structure_widget.setCurrentIndex(1)
        elif current_view == "Sections":
            self._update_sections_view()
            self.structure_widget.setCurrentIndex(2)
        elif current_view == "Imports/Exports":
            self._update_imports_exports_view()
            self.structure_widget.setCurrentIndex(3)
        elif current_view == "Memory Map":
            self._update_memory_map()
            if PYQTGRAPH_AVAILABLE:
                self.structure_widget.setCurrentIndex(4)

    def _update_tree_view(self) -> None:
        """Update the tree view with structure data."""
        self.tree_view.clear()

        if self.binary_format == "PE":
            self._build_pe_tree()
        elif self.binary_format == "ELF":
            self._build_elf_tree()
        elif self.binary_format == "Mach-O":
            self._build_macho_tree()
        else:
            # Generic structure
            self._build_generic_tree()

    def _build_pe_tree(self) -> None:
        """Build PE structure tree."""
        root = QTreeWidgetItem(self.tree_view, ["PE Structure"])

        # DOS Header
        if "dos_header" in self.structure_data:
            dos_item = QTreeWidgetItem(root, ["DOS Header"])
            dos_data = self.structure_data["dos_header"]

            QTreeWidgetItem(dos_item, ["Magic", f"0x{dos_data.get('e_magic', 0):04X}"])
            QTreeWidgetItem(dos_item, ["PE Offset", f"0x{dos_data.get('e_lfanew', 0):08X}"])

        # PE Header
        if "pe_header" in self.structure_data:
            pe_item = QTreeWidgetItem(root, ["PE Header"])
            pe_data = self.structure_data["pe_header"]

            # File Header
            file_header = QTreeWidgetItem(pe_item, ["File Header"])
            file_data = pe_data.get("file_header", {})

            QTreeWidgetItem(file_header, ["Machine", f"0x{file_data.get('machine', 0):04X}"])
            QTreeWidgetItem(file_header, ["Number of Sections", str(file_data.get("number_of_sections", 0))])
            QTreeWidgetItem(file_header, ["Time Date Stamp", str(file_data.get("time_date_stamp", 0))])

            # Optional Header
            opt_header = QTreeWidgetItem(pe_item, ["Optional Header"])
            opt_data = pe_data.get("optional_header", {})

            QTreeWidgetItem(opt_header, ["Magic", f"0x{opt_data.get('magic', 0):04X}"])
            QTreeWidgetItem(opt_header, ["Entry Point", f"0x{opt_data.get('address_of_entry_point', 0):08X}"])
            QTreeWidgetItem(opt_header, ["Image Base", f"0x{opt_data.get('image_base', 0):08X}"])
            QTreeWidgetItem(opt_header, ["Section Alignment", f"0x{opt_data.get('section_alignment', 0):08X}"])
            QTreeWidgetItem(opt_header, ["File Alignment", f"0x{opt_data.get('file_alignment', 0):08X}"])

        # Data Directories
        if "data_directories" in self.structure_data:
            dirs_item = QTreeWidgetItem(root, ["Data Directories"])
            dirs_data = self.structure_data["data_directories"]

            for name, info in dirs_data.items():
                dir_item = QTreeWidgetItem(dirs_item, [name])
                QTreeWidgetItem(dir_item, ["RVA", f"0x{info.get('rva', 0):08X}"])
                QTreeWidgetItem(dir_item, ["Size", f"0x{info.get('size', 0):08X}"])

        # Sections
        if "sections" in self.structure_data:
            sections_item = QTreeWidgetItem(root, ["Sections"])

            for section in self.structure_data["sections"]:
                section_item = QTreeWidgetItem(sections_item, [section.get("name", "Unknown")])

                QTreeWidgetItem(section_item, ["Virtual Address", f"0x{section.get('virtual_address', 0):08X}"])
                QTreeWidgetItem(section_item, ["Virtual Size", f"0x{section.get('virtual_size', 0):08X}"])
                QTreeWidgetItem(section_item, ["Raw Address", f"0x{section.get('raw_address', 0):08X}"])
                QTreeWidgetItem(section_item, ["Raw Size", f"0x{section.get('raw_size', 0):08X}"])

                # Highlight suspicious sections
                if self.highlight_suspicious_cb.isChecked():
                    if self._is_suspicious_section(section):
                        section_item.setForeground(0, QBrush(QColor(255, 100, 100)))

        self.tree_view.expandAll()

    def _build_elf_tree(self) -> None:
        """Build ELF structure tree."""
        root = QTreeWidgetItem(self.tree_view, ["ELF Structure"])

        # ELF Header
        if "elf_header" in self.structure_data:
            header_item = QTreeWidgetItem(root, ["ELF Header"])
            header_data = self.structure_data["elf_header"]

            QTreeWidgetItem(header_item, ["Magic", header_data.get("magic", "")])
            QTreeWidgetItem(header_item, ["Class", header_data.get("class", "")])
            QTreeWidgetItem(header_item, ["Data", header_data.get("data", "")])
            QTreeWidgetItem(header_item, ["Version", str(header_data.get("version", 0))])
            QTreeWidgetItem(header_item, ["OS/ABI", header_data.get("os_abi", "")])
            QTreeWidgetItem(header_item, ["Type", header_data.get("type", "")])
            QTreeWidgetItem(header_item, ["Machine", header_data.get("machine", "")])
            QTreeWidgetItem(header_item, ["Entry Point", f"0x{header_data.get('entry', 0):08X}"])

        # Program Headers
        if "program_headers" in self.structure_data:
            prog_item = QTreeWidgetItem(root, ["Program Headers"])

            for i, phdr in enumerate(self.structure_data["program_headers"]):
                phdr_item = QTreeWidgetItem(prog_item, [f"Segment {i}"])

                QTreeWidgetItem(phdr_item, ["Type", phdr.get("type", "")])
                QTreeWidgetItem(phdr_item, ["Offset", f"0x{phdr.get('offset', 0):08X}"])
                QTreeWidgetItem(phdr_item, ["Virtual Address", f"0x{phdr.get('vaddr', 0):08X}"])
                QTreeWidgetItem(phdr_item, ["Physical Address", f"0x{phdr.get('paddr', 0):08X}"])
                QTreeWidgetItem(phdr_item, ["File Size", f"0x{phdr.get('filesz', 0):08X}"])
                QTreeWidgetItem(phdr_item, ["Memory Size", f"0x{phdr.get('memsz', 0):08X}"])
                QTreeWidgetItem(phdr_item, ["Flags", phdr.get("flags", "")])

        # Section Headers
        if "sections" in self.structure_data:
            sections_item = QTreeWidgetItem(root, ["Sections"])

            for section in self.structure_data["sections"]:
                section_item = QTreeWidgetItem(sections_item, [section.get("name", "Unknown")])

                QTreeWidgetItem(section_item, ["Type", section.get("type", "")])
                QTreeWidgetItem(section_item, ["Address", f"0x{section.get('addr', 0):08X}"])
                QTreeWidgetItem(section_item, ["Offset", f"0x{section.get('offset', 0):08X}"])
                QTreeWidgetItem(section_item, ["Size", f"0x{section.get('size', 0):08X}"])

        self.tree_view.expandAll()

    def _build_generic_tree(self) -> None:
        """Build generic structure tree."""
        root = QTreeWidgetItem(self.tree_view, [f"{self.binary_format} Structure"])

        # Recursively build tree from data
        self._add_dict_to_tree(self.structure_data, root)

        self.tree_view.expandAll()

    def _add_dict_to_tree(self, data: dict | list, parent: QTreeWidgetItem) -> None:
        """Recursively add dictionary/list data to tree."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    item = QTreeWidgetItem(parent, [str(key)])
                    self._add_dict_to_tree(value, item)
                else:
                    QTreeWidgetItem(parent, [str(key), str(value)])

        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    list_item = QTreeWidgetItem(parent, [f"[{i}]"])
                    self._add_dict_to_tree(item, list_item)
                else:
                    QTreeWidgetItem(parent, [f"[{i}]", str(item)])

    def _update_headers_view(self) -> None:
        """Update headers table view."""
        self.headers_table.setRowCount(0)

        if self.binary_format == "PE":
            self._populate_pe_headers()
        elif self.binary_format == "ELF":
            self._populate_elf_headers()
        else:
            self._populate_generic_headers()

    def _populate_pe_headers(self) -> None:
        """Populate PE headers in table."""
        row = 0

        # DOS Header fields
        if "dos_header" in self.structure_data:
            dos = self.structure_data["dos_header"]

            self.headers_table.insertRow(row)
            self.headers_table.setItem(row, 0, QTableWidgetItem("DOS Magic"))
            self.headers_table.setItem(row, 1, QTableWidgetItem(f"0x{dos.get('e_magic', 0):04X}"))
            self.headers_table.setItem(row, 2, QTableWidgetItem("DOS signature (MZ)"))
            row += 1

            self.headers_table.insertRow(row)
            self.headers_table.setItem(row, 0, QTableWidgetItem("PE Offset"))
            self.headers_table.setItem(row, 1, QTableWidgetItem(f"0x{dos.get('e_lfanew', 0):08X}"))
            self.headers_table.setItem(row, 2, QTableWidgetItem("Offset to PE header"))
            row += 1
        # PE Header fields
        if "pe_header" in self.structure_data:
            pe = self.structure_data["pe_header"]

            # Signature
            self.headers_table.insertRow(row)
            self.headers_table.setItem(row, 0, QTableWidgetItem("PE Signature"))
            self.headers_table.setItem(row, 1, QTableWidgetItem(pe.get("signature", "")))
            self.headers_table.setItem(row, 2, QTableWidgetItem("PE file signature"))
            row += 1

            # File header
            if "file_header" in pe:
                fh = pe["file_header"]

                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem("Machine"))
                self.headers_table.setItem(row, 1, QTableWidgetItem(f"0x{fh.get('machine', 0):04X}"))
                self.headers_table.setItem(row, 2, QTableWidgetItem(self._get_machine_name(fh.get("machine", 0))))
                row += 1

                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem("Number of Sections"))
                self.headers_table.setItem(row, 1, QTableWidgetItem(str(fh.get("number_of_sections", 0))))
                self.headers_table.setItem(row, 2, QTableWidgetItem("Total section count"))
                row += 1
            # Optional header
            if "optional_header" in pe:
                oh = pe["optional_header"]

                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem("Entry Point"))
                self.headers_table.setItem(row, 1, QTableWidgetItem(f"0x{oh.get('address_of_entry_point', 0):08X}"))
                self.headers_table.setItem(row, 2, QTableWidgetItem("Program entry point RVA"))
                row += 1

                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem("Image Base"))
                self.headers_table.setItem(row, 1, QTableWidgetItem(f"0x{oh.get('image_base', 0):08X}"))
                self.headers_table.setItem(row, 2, QTableWidgetItem("Preferred load address"))
                row += 1

                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem("Subsystem"))
                self.headers_table.setItem(row, 1, QTableWidgetItem(str(oh.get("subsystem", 0))))
                self.headers_table.setItem(row, 2, QTableWidgetItem(self._get_subsystem_name(oh.get("subsystem", 0))))
                row += 1

    def _update_sections_view(self) -> None:
        """Update sections table view."""
        self.sections_table.setRowCount(0)

        if "sections" not in self.structure_data:
            return
        sections = self.structure_data["sections"]

        for row, section in enumerate(sections):
            self.sections_table.insertRow(row)

            # Section name
            name_item = QTableWidgetItem(section.get("name", ""))
            self.sections_table.setItem(row, 0, name_item)

            # Virtual address
            va = section.get("virtual_address", 0)
            self.sections_table.setItem(row, 1, QTableWidgetItem(f"0x{va:08X}"))

            # Virtual size
            vs = section.get("virtual_size", 0)
            self.sections_table.setItem(row, 2, QTableWidgetItem(f"0x{vs:08X}"))

            # Raw address
            ra = section.get("raw_address", 0)
            self.sections_table.setItem(row, 3, QTableWidgetItem(f"0x{ra:08X}"))

            # Raw size
            rs = section.get("raw_size", 0)
            self.sections_table.setItem(row, 4, QTableWidgetItem(f"0x{rs:08X}"))

            # Characteristics
            chars = section.get("characteristics", 0)
            self.sections_table.setItem(row, 5, QTableWidgetItem(f"0x{chars:08X}"))
            # Highlight suspicious sections
            if self.highlight_suspicious_cb.isChecked():
                if self._is_suspicious_section(section):
                    for col in range(6):
                        item = self.sections_table.item(row, col)
                        if item:
                            item.setBackground(QBrush(QColor(255, 200, 200)))

    def _update_imports_exports_view(self) -> None:
        """Update imports/exports view."""
        # Clear tables
        self.imports_table.setRowCount(0)
        self.exports_table.setRowCount(0)

        # Populate imports
        if "imports" in self.structure_data:
            imports = self.structure_data["imports"]
            row = 0

            for dll_name, functions in imports.items():
                for func in functions:
                    self.imports_table.insertRow(row)
                    self.imports_table.setItem(row, 0, QTableWidgetItem(dll_name))
                    self.imports_table.setItem(row, 1, QTableWidgetItem(func.get("name", "")))
                    self.imports_table.setItem(row, 2, QTableWidgetItem(str(func.get("ordinal", ""))))

                    # Highlight suspicious imports
                    if self.highlight_suspicious_cb.isChecked():
                        if self._is_suspicious_import(func.get("name", "")):
                            for col in range(3):
                                item = self.imports_table.item(row, col)
                                if item:
                                    item.setForeground(QBrush(QColor(255, 100, 100)))
                    row += 1
        # Populate exports
        if "exports" in self.structure_data:
            exports = self.structure_data["exports"]

            for row, export in enumerate(exports):
                self.exports_table.insertRow(row)
                self.exports_table.setItem(row, 0, QTableWidgetItem(str(export.get("ordinal", ""))))
                self.exports_table.setItem(row, 1, QTableWidgetItem(export.get("name", "")))
                self.exports_table.setItem(row, 2, QTableWidgetItem(f"0x{export.get('address', 0):08X}"))
                self.exports_table.setItem(row, 3, QTableWidgetItem(export.get("forwarded", "")))

    def _update_memory_map(self) -> None:
        """Update memory map visualization."""
        if not PYQTGRAPH_AVAILABLE or "sections" not in self.structure_data:
            return

        self.memory_map.clear()

        sections = self.structure_data["sections"]

        # Create memory map visualization
        for i, section in enumerate(sections):
            va = section.get("virtual_address", 0)
            vs = section.get("virtual_size", 0)

            # Create rectangle for section
            rect = pg.QtWidgets.QGraphicsRectItem(va, i, vs, 0.8)

            # Color based on characteristics
            if self._is_executable_section(section):
                rect.setBrush(pg.mkBrush(255, 100, 100, 150))  # Red for executable
            elif self._is_writable_section(section):
                rect.setBrush(pg.mkBrush(100, 100, 255, 150))  # Blue for writable
            else:
                rect.setBrush(pg.mkBrush(100, 255, 100, 150))  # Green for read-only
            self.memory_map.addItem(rect)

            # Add text label
            text = pg.TextItem(section.get("name", ""), anchor=(0, 0.5))
            text.setPos(va, i + 0.4)
            self.memory_map.addItem(text)

        # Set axis labels
        self.memory_map.setLabel("left", "Sections")
        self.memory_map.setLabel("bottom", "Virtual Address")

        # Set Y axis ticks to section names
        y_ticks = [(i, section.get("name", "")) for i, section in enumerate(sections)]
        self.memory_map.getAxis("left").setTicks([y_ticks])

    def update_details(self) -> None:
        """Update the details panel."""
        if not self.structure_data:
            return

        details = f"=== {self.binary_format} Structure Analysis ===\n\n"

        # Basic info
        details += f"Format: {self.binary_format}\n"
        details += f"Architecture: {self.structure_data.get('architecture', 'Unknown')}\n"
        details += f"Endianness: {self.structure_data.get('endianness', 'Unknown')}\n\n"

        # Statistics
        if "sections" in self.structure_data:
            sections = self.structure_data["sections"]
            details += f"Total Sections: {len(sections)}\n"

            exec_count = sum(1 for s in sections if self._is_executable_section(s))
            write_count = sum(1 for s in sections if self._is_writable_section(s))

            details += f"Executable Sections: {exec_count}\n"
            details += f"Writable Sections: {write_count}\n\n"
        # Suspicious indicators
        suspicious = []

        if "sections" in self.structure_data:
            for section in self.structure_data["sections"]:
                if self._is_suspicious_section(section):
                    suspicious.append(f"Section '{section.get('name', '')}' has suspicious characteristics")

        if "imports" in self.structure_data:
            imports = self.structure_data["imports"]
            for _dll, funcs in imports.items():
                for func in funcs:
                    if self._is_suspicious_import(func.get("name", "")):
                        suspicious.append(f"Suspicious import: {func.get('name', '')}")

        if suspicious:
            details += "WARNING️ Suspicious Indicators:\n"
            for item in suspicious[:10]:  # Show first 10
                details += f"   {item}\n"

        self.details_text.setText(details)

    # Helper methods
    def _is_suspicious_section(self, section: dict[str, Any]) -> bool:
        """Check if a section has suspicious characteristics."""
        name = section.get("name", "").lower()

        # Check for unusual section names
        suspicious_names = [".upx", ".aspack", ".themida", ".vmp", ".enigma"]
        if any(sus in name for sus in suspicious_names):
            return True

        # Check for writable + executable
        chars = section.get("characteristics", 0)
        if self.binary_format == "PE":
            EXECUTE = 0x20000000
            WRITE = 0x80000000
            if (chars & EXECUTE) and (chars & WRITE):
                return True
        # Check for size anomalies
        virtual_size = section.get("virtual_size", 0)
        raw_size = section.get("raw_size", 0)

        if virtual_size > 0 and raw_size == 0:
            return True

        return raw_size > virtual_size * 2

    def _is_suspicious_import(self, func_name: str) -> bool:
        """Check if an import is suspicious."""
        if not func_name:
            return False

        suspicious_funcs = [
            "VirtualProtect",
            "VirtualAlloc",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "SetWindowsHookEx",
            "GetProcAddress",
            "LoadLibrary",
            "OpenProcess",
            "TerminateProcess",
            "RegSetValue",
            "RegCreateKey",
            "WinExec",
            "ShellExecute",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
        ]

        return func_name in suspicious_funcs

    def _is_executable_section(self, section: dict[str, Any]) -> bool:
        """Check if section is executable."""
        chars = section.get("characteristics", 0)

        if self.binary_format == "PE":
            return bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        if self.binary_format == "ELF":
            return bool(chars & 0x1)  # PF_X

        return False

    def _is_writable_section(self, section: dict[str, Any]) -> bool:
        """Check if section is writable."""
        chars = section.get("characteristics", 0)

        if self.binary_format == "PE":
            return bool(chars & 0x80000000)  # IMAGE_SCN_MEM_WRITE
        if self.binary_format == "ELF":
            return bool(chars & 0x2)  # PF_W

        return False

    def _get_machine_name(self, machine: int) -> str:
        """Get machine type name."""
        machines = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (AMD64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
            0x0200: "IA64",
        }
        return machines.get(machine, f"Unknown (0x{machine:04X})")

    def _get_subsystem_name(self, subsystem: int) -> str:
        """Get subsystem name."""
        subsystems = {
            0: "Unknown",
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "Xbox",
            16: "Windows Boot Application",
        }
        return subsystems.get(subsystem, f"Unknown ({subsystem})")

    def _populate_elf_headers(self) -> None:
        """Populate ELF headers in table."""
        row = 0

        if "elf_header" in self.structure_data:
            header = self.structure_data["elf_header"]

            # Add ELF header fields
            fields = [
                ("Magic", header.get("magic", ""), "ELF file signature"),
                ("Class", header.get("class", ""), "32-bit or 64-bit"),
                ("Data", header.get("data", ""), "Endianness"),
                ("Version", str(header.get("version", 0)), "ELF version"),
                ("OS/ABI", header.get("os_abi", ""), "Target OS ABI"),
                ("Type", header.get("type", ""), "File type"),
                ("Machine", header.get("machine", ""), "Target architecture"),
                ("Entry Point", f"0x{header.get('entry', 0):08X}", "Program entry point"),
            ]

            for field, value, desc in fields:
                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem(field))
                self.headers_table.setItem(row, 1, QTableWidgetItem(value))
                self.headers_table.setItem(row, 2, QTableWidgetItem(desc))
                row += 1

    def _populate_generic_headers(self) -> None:
        """Populate generic headers."""
        row = 0

        # Add any header-like data from structure
        for key, value in self.structure_data.items():
            if not isinstance(value, (dict, list)):
                self.headers_table.insertRow(row)
                self.headers_table.setItem(row, 0, QTableWidgetItem(str(key)))
                self.headers_table.setItem(row, 1, QTableWidgetItem(str(value)))
                self.headers_table.setItem(row, 2, QTableWidgetItem(""))
                row += 1

    def _on_tree_selection(self) -> None:
        """Handle tree item selection."""
        items = self.tree_view.selectedItems()
        if items:
            item = items[0]
            # Get path to item
            path = []
            current = item
            while current:
                path.insert(0, current.text(0))
                current = current.parent()

            # Emit signal with path
            if len(path) > 1:
                self.header_field_selected.emit(path[0], path[-1], item.text(1) if item.columnCount() > 1 else "")

    def _on_section_selection(self) -> None:
        """Handle section selection."""
        items = self.sections_table.selectedItems()
        if items:
            row = items[0].row()
            if row < len(self.structure_data.get("sections", [])):
                section = self.structure_data["sections"][row]
                self.section_selected.emit(section.get("name", ""), section)

    def export_structure(self) -> None:
        """Export structure data."""
        import json

        from intellicrack.handlers.pyqt6_handler import QFileDialog, QMessageBox

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Structure Data",
            "structure_analysis.json",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)",
        )

        if filename:
            try:
                if filename.endswith(".json"):
                    with open(filename, "w") as f:
                        json.dump(self.structure_data, f, indent=2)
                else:
                    # Export as formatted text
                    with open(filename, "w") as f:
                        f.write(self._format_structure_text())

                # Show success message

                QMessageBox.information(self, "Export Complete", f"Structure exported to {filename}")

            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e!s}")

    def _format_structure_text(self) -> str:
        """Format structure data as readable text."""
        text = "Binary Structure Analysis\n"
        text += f"{'=' * 50}\n\n"

        text += f"Format: {self.binary_format}\n"
        text += f"Architecture: {self.structure_data.get('architecture', 'Unknown')}\n\n"

        # Sections
        if "sections" in self.structure_data:
            text += "Sections:\n"
            text += "-" * 40 + "\n"
            for section in self.structure_data["sections"]:
                text += f"  {section.get('name', 'Unknown'):16} "
                text += f"VA: 0x{section.get('virtual_address', 0):08X} "
                text += f"Size: 0x{section.get('virtual_size', 0):08X}\n"

        return text
