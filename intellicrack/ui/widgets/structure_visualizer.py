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

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize structure visualizer widget with binary structure analysis capabilities.

        Args:
            parent: Parent widget for this widget, or None for no parent.
        """
        super().__init__(parent)
        self.current_binary: str | None = None
        self.structures: dict[str, Any] = {}
        self.structure_data: dict[str, Any] = {}
        self.binary_format: str = "Unknown"
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the UI components.

        Initializes all UI widgets including controls, splitter, tabs, and detail panels.

        Returns:
            None
        """
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
        """Initialize the different view widgets.

        Creates and configures all view tabs including tree view, headers table,
        sections table, imports/exports, and memory map visualization.

        Returns:
            None
        """
        # Tree view
        self.tree_view = QTreeWidget()
        self.tree_view.setHeaderLabel("Binary Structure")
        self.tree_view.itemSelectionChanged.connect(self._on_tree_selection)
        self.structure_widget.addTab(self.tree_view, "Tree")

        # Headers table
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(3)
        self.headers_table.setHorizontalHeaderLabels(["Field", "Value", "Description"])
        if header := self.headers_table.horizontalHeader():
            header.setStretchLastSection(True)
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
        """Set structure data for visualization.

        Args:
            data: Dictionary containing binary structure information including headers,
                sections, imports/exports, and other binary format-specific data.

        Returns:
            None
        """
        self.structure_data = data
        self.binary_format = data.get("format", "Unknown")

        # Update all views
        self.update_view()
        self.update_details()

    def load_structure(self, data: dict[str, Any]) -> None:
        """Load structure data for visualization (alias for set_structure_data).

        Args:
            data: Dictionary containing binary structure information.

        Returns:
            None
        """
        self.set_structure_data(data)

    def update_view(self) -> None:
        """Update the current view.

        Updates the visualization based on the currently selected view mode
        (Tree View, Headers, Sections, Imports/Exports, or Memory Map).

        Returns:
            None
        """
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
        """Update the tree view with structure data.

        Clears the tree view and populates it with binary structure information
        based on the detected binary format (PE, ELF, Mach-O, or generic).

        Returns:
            None
        """
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
        """Build PE structure tree.

        Constructs a tree view representation of PE (Portable Executable) binary structure
        including DOS header, PE header, sections, and data directories.

        Returns:
            None
        """
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
                if self.highlight_suspicious_cb.isChecked() and self._is_suspicious_section(section):
                    section_item.setForeground(0, QBrush(QColor(255, 100, 100)))

        self.tree_view.expandAll()

    def _build_elf_tree(self) -> None:
        """Build ELF structure tree.

        Constructs a tree view representation of ELF (Executable and Linkable Format) binary
        structure including headers, program headers, and sections.

        Returns:
            None
        """
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

    def _build_macho_tree(self) -> None:
        """Build Mach-O structure tree for macOS/iOS binaries.

        Constructs a tree view representation of Mach-O binary structure including
        headers, load commands, sections, and dynamic libraries.

        Returns:
            None
        """
        root = QTreeWidgetItem(self.tree_view, ["Mach-O Structure"])

        if "macho_header" in self.structure_data:
            header_item = QTreeWidgetItem(root, ["Mach-O Header"])
            header_data = self.structure_data["macho_header"]

            magic = header_data.get("magic", 0)
            magic_str = self._get_macho_magic_name(magic)
            QTreeWidgetItem(header_item, ["Magic", f"0x{magic:08X} ({magic_str})"])

            cpu_type = header_data.get("cpu_type", 0)
            cpu_name = self._get_macho_cpu_name(cpu_type)
            QTreeWidgetItem(header_item, ["CPU Type", f"0x{cpu_type:08X} ({cpu_name})"])

            cpu_subtype = header_data.get("cpu_subtype", 0)
            QTreeWidgetItem(header_item, ["CPU Subtype", f"0x{cpu_subtype:08X}"])

            file_type = header_data.get("file_type", 0)
            file_type_name = self._get_macho_file_type(file_type)
            QTreeWidgetItem(header_item, ["File Type", f"{file_type} ({file_type_name})"])

            QTreeWidgetItem(header_item, ["Number of Load Commands", str(header_data.get("ncmds", 0))])
            QTreeWidgetItem(header_item, ["Size of Load Commands", f"0x{header_data.get('sizeofcmds', 0):08X}"])

            flags = header_data.get("flags", 0)
            QTreeWidgetItem(header_item, ["Flags", f"0x{flags:08X}"])

            flags_item = QTreeWidgetItem(header_item, ["Flag Details"])
            self._add_macho_flags(flags_item, flags)

        if "load_commands" in self.structure_data:
            lc_root = QTreeWidgetItem(root, ["Load Commands"])

            for i, cmd in enumerate(self.structure_data["load_commands"]):
                cmd_type = cmd.get("cmd", 0)
                cmd_name = cmd.get("cmd_name", self._get_macho_load_cmd_name(cmd_type))
                cmd_item = QTreeWidgetItem(lc_root, [f"[{i}] {cmd_name}"])

                QTreeWidgetItem(cmd_item, ["Command", f"0x{cmd_type:08X}"])
                QTreeWidgetItem(cmd_item, ["Size", f"0x{cmd.get('cmdsize', 0):08X}"])

                if cmd_name in ("LC_SEGMENT", "LC_SEGMENT_64"):
                    seg_name = cmd.get("segname", "")
                    QTreeWidgetItem(cmd_item, ["Segment Name", seg_name])
                    QTreeWidgetItem(cmd_item, ["VM Address", f"0x{cmd.get('vmaddr', 0):016X}"])
                    QTreeWidgetItem(cmd_item, ["VM Size", f"0x{cmd.get('vmsize', 0):016X}"])
                    QTreeWidgetItem(cmd_item, ["File Offset", f"0x{cmd.get('fileoff', 0):016X}"])
                    QTreeWidgetItem(cmd_item, ["File Size", f"0x{cmd.get('filesize', 0):016X}"])

                    if "sections" in cmd:
                        sections_item = QTreeWidgetItem(cmd_item, ["Sections"])
                        for section in cmd["sections"]:
                            sec_name = section.get("sectname", "Unknown")
                            sec_item = QTreeWidgetItem(sections_item, [sec_name])
                            QTreeWidgetItem(sec_item, ["Address", f"0x{section.get('addr', 0):016X}"])
                            QTreeWidgetItem(sec_item, ["Size", f"0x{section.get('size', 0):016X}"])
                            QTreeWidgetItem(sec_item, ["Offset", f"0x{section.get('offset', 0):08X}"])

                elif cmd_name == "LC_UUID":
                    uuid_bytes = cmd.get("uuid", b"")
                    if isinstance(uuid_bytes, bytes):
                        uuid_str = uuid_bytes.hex()
                    else:
                        uuid_str = str(uuid_bytes)
                    QTreeWidgetItem(cmd_item, ["UUID", uuid_str])

                elif cmd_name in ("LC_DYLIB", "LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB"):
                    QTreeWidgetItem(cmd_item, ["Library", cmd.get("name", "")])
                    QTreeWidgetItem(cmd_item, ["Version", cmd.get("current_version", "")])
                    QTreeWidgetItem(cmd_item, ["Compatibility", cmd.get("compatibility_version", "")])

                elif cmd_name == "LC_MAIN":
                    QTreeWidgetItem(cmd_item, ["Entry Offset", f"0x{cmd.get('entryoff', 0):016X}"])
                    QTreeWidgetItem(cmd_item, ["Stack Size", f"0x{cmd.get('stacksize', 0):016X}"])

                elif cmd_name == "LC_CODE_SIGNATURE":
                    QTreeWidgetItem(cmd_item, ["Data Offset", f"0x{cmd.get('dataoff', 0):08X}"])
                    QTreeWidgetItem(cmd_item, ["Data Size", f"0x{cmd.get('datasize', 0):08X}"])

        if "sections" in self.structure_data:
            sections_item = QTreeWidgetItem(root, ["Sections"])

            for section in self.structure_data["sections"]:
                section_name = section.get("name", section.get("sectname", "Unknown"))
                segment_name = section.get("segment", section.get("segname", ""))
                display_name = f"{segment_name},{section_name}" if segment_name else section_name

                section_item = QTreeWidgetItem(sections_item, [display_name])

                QTreeWidgetItem(section_item, ["Address", f"0x{section.get('addr', section.get('virtual_address', 0)):016X}"])
                QTreeWidgetItem(section_item, ["Size", f"0x{section.get('size', section.get('virtual_size', 0)):016X}"])
                QTreeWidgetItem(section_item, ["Offset", f"0x{section.get('offset', section.get('raw_address', 0)):08X}"])
                QTreeWidgetItem(section_item, ["Align", str(section.get("align", 0))])

                if self.highlight_suspicious_cb.isChecked() and self._is_suspicious_section(section):
                    section_item.setForeground(0, QBrush(QColor(255, 100, 100)))

        if "dylibs" in self.structure_data or "libraries" in self.structure_data:
            if libs := self.structure_data.get("dylibs", self.structure_data.get("libraries", [])):
                libs_item = QTreeWidgetItem(root, ["Dynamic Libraries"])
                for lib in libs:
                    if isinstance(lib, dict):
                        lib_name = lib.get("name", lib.get("path", "Unknown"))
                    else:
                        lib_name = str(lib)
                    QTreeWidgetItem(libs_item, [lib_name])

        if "symbols" in self.structure_data:
            if symbols := self.structure_data["symbols"]:
                symbols_item = QTreeWidgetItem(root, [f"Symbols ({len(symbols)})"])
                for sym in symbols[:100]:
                    if isinstance(sym, dict):
                        sym_name = sym.get("name", "Unknown")
                        sym_addr = sym.get("address", sym.get("value", 0))
                        sym_item = QTreeWidgetItem(symbols_item, [sym_name])
                        QTreeWidgetItem(sym_item, ["Address", f"0x{sym_addr:016X}"])
                    else:
                        QTreeWidgetItem(symbols_item, [str(sym)])

                if len(symbols) > 100:
                    QTreeWidgetItem(symbols_item, [f"... and {len(symbols) - 100} more symbols"])

        self.tree_view.expandAll()

    def _get_macho_magic_name(self, magic: int) -> str:
        """Get Mach-O magic number name.

        Args:
            magic: The magic number value to look up. Standard Mach-O magic
                values include 0xFEEDFACE (32-bit), 0xFEEDFACF (64-bit), and
                0xCAFEBABE (Universal).

        Returns:
            Human-readable name for the magic number or 'Unknown' if not found.
        """
        magic_names = {
            0xFEEDFACE: "MH_MAGIC (32-bit)",
            0xCEFAEDFE: "MH_CIGAM (32-bit, swapped)",
            0xFEEDFACF: "MH_MAGIC_64 (64-bit)",
            0xCFFAEDFE: "MH_CIGAM_64 (64-bit, swapped)",
            0xCAFEBABE: "FAT_MAGIC (Universal)",
            0xBEBAFECA: "FAT_CIGAM (Universal, swapped)",
        }
        return magic_names.get(magic, "Unknown")

    def _get_macho_cpu_name(self, cpu_type: int) -> str:
        """Get Mach-O CPU type name.

        Args:
            cpu_type: The CPU type value to look up. Common values include 7
                (x86), 0x01000007 (x86_64), 12 (ARM), and 0x0100000C (ARM64).

        Returns:
            Human-readable CPU type name or 'Unknown' with hex value if not found.
        """
        cpu_names = {
            1: "VAX",
            6: "MC680x0",
            7: "x86",
            0x01000007: "x86_64",
            10: "MC98000",
            11: "HPPA",
            12: "ARM",
            0x0100000C: "ARM64",
            13: "MC88000",
            14: "SPARC",
            15: "i860",
            18: "PowerPC",
            0x01000012: "PowerPC64",
        }
        return cpu_names.get(cpu_type, f"Unknown (0x{cpu_type:X})")

    def _get_macho_file_type(self, file_type: int) -> str:
        """Get Mach-O file type name.

        Args:
            file_type: The file type value to look up. Common values include 1
                (MH_OBJECT), 2 (MH_EXECUTE), 6 (MH_DYLIB), and 8 (MH_BUNDLE).

        Returns:
            Human-readable file type name or 'Unknown' with value if not found.
        """
        file_types = {
            1: "MH_OBJECT",
            2: "MH_EXECUTE",
            3: "MH_FVMLIB",
            4: "MH_CORE",
            5: "MH_PRELOAD",
            6: "MH_DYLIB",
            7: "MH_DYLINKER",
            8: "MH_BUNDLE",
            9: "MH_DYLIB_INTERFACE",
            10: "MH_DSYM",
            11: "MH_KEXT_BUNDLE",
            12: "MH_FILESET",
        }
        return file_types.get(file_type, f"Unknown ({file_type})")

    def _get_macho_load_cmd_name(self, cmd: int) -> str:
        """Get Mach-O load command name.

        Args:
            cmd: The load command value to look up. Standard load commands include
                0x1 (LC_SEGMENT), 0x19 (LC_SEGMENT_64), 0x1B (LC_UUID), and
                0x1D (LC_CODE_SIGNATURE).

        Returns:
            Human-readable load command name or 'LC_UNKNOWN' with hex value if not found.
        """
        cmd_names = {
            0x1: "LC_SEGMENT",
            0x2: "LC_SYMTAB",
            0x3: "LC_SYMSEG",
            0x4: "LC_THREAD",
            0x5: "LC_UNIXTHREAD",
            0x6: "LC_LOADFVMLIB",
            0x7: "LC_IDFVMLIB",
            0x8: "LC_IDENT",
            0x9: "LC_FVMFILE",
            0xA: "LC_PREPAGE",
            0xB: "LC_DYSYMTAB",
            0xC: "LC_LOAD_DYLIB",
            0xD: "LC_ID_DYLIB",
            0xE: "LC_LOAD_DYLINKER",
            0xF: "LC_ID_DYLINKER",
            0x10: "LC_PREBOUND_DYLIB",
            0x11: "LC_ROUTINES",
            0x12: "LC_SUB_FRAMEWORK",
            0x13: "LC_SUB_UMBRELLA",
            0x14: "LC_SUB_CLIENT",
            0x15: "LC_SUB_LIBRARY",
            0x16: "LC_TWOLEVEL_HINTS",
            0x17: "LC_PREBIND_CKSUM",
            0x80000018: "LC_LOAD_WEAK_DYLIB",
            0x19: "LC_SEGMENT_64",
            0x1A: "LC_ROUTINES_64",
            0x1B: "LC_UUID",
            0x8000001C: "LC_RPATH",
            0x1D: "LC_CODE_SIGNATURE",
            0x1E: "LC_SEGMENT_SPLIT_INFO",
            0x8000001F: "LC_REEXPORT_DYLIB",
            0x20: "LC_LAZY_LOAD_DYLIB",
            0x21: "LC_ENCRYPTION_INFO",
            0x22: "LC_DYLD_INFO",
            0x80000022: "LC_DYLD_INFO_ONLY",
            0x80000023: "LC_LOAD_UPWARD_DYLIB",
            0x24: "LC_VERSION_MIN_MACOSX",
            0x25: "LC_VERSION_MIN_IPHONEOS",
            0x26: "LC_FUNCTION_STARTS",
            0x27: "LC_DYLD_ENVIRONMENT",
            0x80000028: "LC_MAIN",
            0x29: "LC_DATA_IN_CODE",
            0x2A: "LC_SOURCE_VERSION",
            0x2B: "LC_DYLIB_CODE_SIGN_DRS",
            0x2C: "LC_ENCRYPTION_INFO_64",
            0x2D: "LC_LINKER_OPTION",
            0x2E: "LC_LINKER_OPTIMIZATION_HINT",
            0x2F: "LC_VERSION_MIN_TVOS",
            0x30: "LC_VERSION_MIN_WATCHOS",
            0x31: "LC_NOTE",
            0x32: "LC_BUILD_VERSION",
            0x80000033: "LC_DYLD_EXPORTS_TRIE",
            0x80000034: "LC_DYLD_CHAINED_FIXUPS",
        }
        return cmd_names.get(cmd, f"LC_UNKNOWN (0x{cmd:X})")

    def _add_macho_flags(self, parent: QTreeWidgetItem, flags: int) -> None:
        """Add Mach-O header flags as tree items.

        Args:
            parent: The parent tree widget item to add flags to.
            flags: The flags value to decode and display.

        Returns:
            None
        """
        flag_definitions = [
            (0x1, "MH_NOUNDEFS", "No undefined references"),
            (0x2, "MH_INCRLINK", "Incremental link"),
            (0x4, "MH_DYLDLINK", "Input for dynamic linker"),
            (0x8, "MH_BINDATLOAD", "Bind undefined refs at load"),
            (0x10, "MH_PREBOUND", "Prebound"),
            (0x20, "MH_SPLIT_SEGS", "Split read-only and read-write segments"),
            (0x40, "MH_LAZY_INIT", "Lazy init"),
            (0x80, "MH_TWOLEVEL", "Two-level namespace bindings"),
            (0x100, "MH_FORCE_FLAT", "Force flat namespace"),
            (0x200, "MH_NOMULTIDEFS", "No multiple definitions"),
            (0x400, "MH_NOFIXPREBINDING", "Do not notify prebinding agent"),
            (0x800, "MH_PREBINDABLE", "Not prebound but can be"),
            (0x1000, "MH_ALLMODSBOUND", "All modules bound"),
            (0x2000, "MH_SUBSECTIONS_VIA_SYMBOLS", "Safe to divide sections"),
            (0x4000, "MH_CANONICAL", "Canonicalized via unprebind"),
            (0x8000, "MH_WEAK_DEFINES", "Contains weak symbols"),
            (0x10000, "MH_BINDS_TO_WEAK", "Uses weak symbols"),
            (0x20000, "MH_ALLOW_STACK_EXECUTION", "Allow stack execution"),
            (0x40000, "MH_ROOT_SAFE", "Safe for UID 0"),
            (0x80000, "MH_SETUID_SAFE", "Safe for setuid"),
            (0x100000, "MH_NO_REEXPORTED_DYLIBS", "No re-exported dylibs"),
            (0x200000, "MH_PIE", "Position Independent Executable"),
            (0x400000, "MH_DEAD_STRIPPABLE_DYLIB", "Dead-strippable dylib"),
            (0x800000, "MH_HAS_TLV_DESCRIPTORS", "Has thread-local variables"),
            (0x1000000, "MH_NO_HEAP_EXECUTION", "No heap execution"),
            (0x2000000, "MH_APP_EXTENSION_SAFE", "App extension safe"),
        ]

        for flag_value, flag_name, description in flag_definitions:
            if flags & flag_value:
                QTreeWidgetItem(parent, [flag_name, description])

    def _build_generic_tree(self) -> None:
        """Build generic structure tree.

        Constructs a tree view representation of binary structure for unknown formats
        using a generic dictionary/list traversal approach.

        Returns:
            None
        """
        root = QTreeWidgetItem(self.tree_view, [f"{self.binary_format} Structure"])

        # Recursively build tree from data
        self._add_dict_to_tree(self.structure_data, root)

        self.tree_view.expandAll()

    def _add_dict_to_tree(self, data: dict[str, Any] | list[Any], parent: QTreeWidgetItem) -> None:
        """Recursively add dictionary/list data to tree.

        Args:
            data: Dictionary or list to traverse and add to the tree.
            parent: The parent tree widget item to add data to.

        Returns:
            None
        """
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
        """Update headers table view.

        Clears and populates the headers table based on the binary format
        (PE, ELF, or generic).

        Returns:
            None
        """
        self.headers_table.setRowCount(0)

        if self.binary_format == "PE":
            self._populate_pe_headers()
        elif self.binary_format == "ELF":
            self._populate_elf_headers()
        else:
            self._populate_generic_headers()

    def _populate_pe_headers(self) -> None:
        """Populate PE headers in table.

        Extracts DOS header, PE header, file header, and optional header
        fields from the structure data and populates the headers table.

        Returns:
            None
        """
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
        """Update sections table view.

        Clears and populates the sections table with binary section information
        including names, addresses, and sizes, with highlighting for suspicious sections.

        Returns:
            None
        """
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
            if self.highlight_suspicious_cb.isChecked() and self._is_suspicious_section(section):
                for col in range(6):
                    if item := self.sections_table.item(row, col):
                        item.setBackground(QBrush(QColor(255, 200, 200)))

    def _update_imports_exports_view(self) -> None:
        """Update imports/exports view.

        Clears and populates the imports and exports tables with imported/exported
        functions, with highlighting for suspicious imports.

        Returns:
            None
        """
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
                    if self.highlight_suspicious_cb.isChecked() and self._is_suspicious_import(func.get("name", "")):
                        for col in range(3):
                            if item := self.imports_table.item(row, col):
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
        """Update memory map visualization.

        Creates a visual representation of binary sections in memory with
        color-coded characteristics (executable, writable, read-only).

        Returns:
            None
        """
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
        """Update the details panel.

        Refreshes the details text panel with structure analysis summary,
        section statistics, and suspicious indicator warnings.

        Returns:
            None
        """
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

            exec_count = sum(bool(self._is_executable_section(s)) for s in sections)
            write_count = sum(bool(self._is_writable_section(s)) for s in sections)

            details += f"Executable Sections: {exec_count}\n"
            details += f"Writable Sections: {write_count}\n\n"
        # Suspicious indicators
        suspicious: list[str] = []

        if "sections" in self.structure_data:
            suspicious.extend(
                f"Section '{section.get('name', '')}' has suspicious characteristics"
                for section in self.structure_data["sections"]
                if self._is_suspicious_section(section)
            )
        if "imports" in self.structure_data:
            imports = self.structure_data["imports"]
            for funcs in imports.values():
                suspicious.extend(
                    f"Suspicious import: {func.get('name', '')}" for func in funcs if self._is_suspicious_import(func.get("name", ""))
                )
        if suspicious:
            details += "WARNING️ Suspicious Indicators:\n"
            for item in suspicious[:10]:  # Show first 10
                details += f"   {item}\n"

        self.details_text.setText(details)

    # Helper methods
    def _is_suspicious_section(self, section: dict[str, Any]) -> bool:
        """Check if a section has suspicious characteristics.

        Examines section name, characteristics flags, and size anomalies to
        identify potentially obfuscated, packed, or modified code sections.

        Args:
            section: Section information dictionary to analyze. Expected keys
                include 'name', 'characteristics', 'virtual_size', and 'raw_size'.

        Returns:
            True if the section exhibits suspicious characteristics, False otherwise.
        """
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

        if isinstance(virtual_size, int) and isinstance(raw_size, int):
            return raw_size > virtual_size * 2
        return False

    def _is_suspicious_import(self, func_name: str) -> bool:
        """Check if an import is suspicious.

        Identifies commonly exploited or suspicious API functions that may
        indicate anti-debugging, code injection, or system manipulation.

        Args:
            func_name: Function name to check against suspicious function list.
                Examples include VirtualProtect, CreateRemoteThread, and
                IsDebuggerPresent.

        Returns:
            True if the function is in the suspicious imports list, False otherwise.
        """
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
        """Check if section is executable.

        Tests the characteristics flags for execute permission based on binary
        format (PE uses 0x20000000, ELF uses 0x1 flag).

        Args:
            section: Section information dictionary to check. Requires the
                'characteristics' key to determine executable status.

        Returns:
            True if the section has executable characteristics, False otherwise.
        """
        chars = section.get("characteristics", 0)

        if self.binary_format == "PE":
            return bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        return bool(chars & 0x1) if self.binary_format == "ELF" else False

    def _is_writable_section(self, section: dict[str, Any]) -> bool:
        """Check if section is writable.

        Tests the characteristics flags for write permission based on binary
        format (PE uses 0x80000000, ELF uses 0x2 flag).

        Args:
            section: Section information dictionary to check. Requires the
                'characteristics' key to determine writable status.

        Returns:
            True if the section has writable characteristics, False otherwise.
        """
        chars = section.get("characteristics", 0)

        if self.binary_format == "PE":
            return bool(chars & 0x80000000)  # IMAGE_SCN_MEM_WRITE
        return bool(chars & 0x2) if self.binary_format == "ELF" else False

    def _get_machine_name(self, machine: int) -> str:
        """Get machine type name.

        Maps PE machine type values to human-readable CPU architecture names.

        Args:
            machine: The machine type value to look up. Common PE machine values
                include 0x014C (x86), 0x8664 (x64), 0x01C0 (ARM), and 0xAA64 (ARM64).

        Returns:
            Human-readable machine type name or 'Unknown' with hex value if not found.
        """
        machines = {
            0x014C: "x86 (32-bit)",
            0x8664: "x64 (AMD64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
            0x0200: "IA64",
        }
        return machines.get(machine, f"Unknown (0x{machine:04X})")

    def _get_subsystem_name(self, subsystem: int) -> str:
        """Get subsystem name.

        Maps PE subsystem values to human-readable subsystem type names.

        Args:
            subsystem: The subsystem value to look up. Common PE subsystem values
                include 2 (Windows GUI), 3 (Windows Console), and 10 (EFI Application).

        Returns:
            Human-readable subsystem name or 'Unknown' with value if not found.
        """
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
        """Populate ELF headers in table.

        Extracts ELF header fields from structure data and populates
        the headers table with standard ELF header information.

        Returns:
            None
        """
        if "elf_header" not in self.structure_data:
            return
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

        for row, (field, value, desc) in enumerate(fields):
            self.headers_table.insertRow(row)
            self.headers_table.setItem(row, 0, QTableWidgetItem(field))
            self.headers_table.setItem(row, 1, QTableWidgetItem(value))
            self.headers_table.setItem(row, 2, QTableWidgetItem(desc))

    def _populate_generic_headers(self) -> None:
        """Populate generic headers.

        Extracts all non-dict and non-list data from structure data
        and populates the headers table with generic information.

        Returns:
            None
        """
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
        """Handle tree item selection.

        Emits a signal when a tree item is selected with the header type
        and selected field information.

        Returns:
            None
        """
        if items := self.tree_view.selectedItems():
            item = items[0]
            # Get path to item
            path: list[str] = []
            current: QTreeWidgetItem | None = item
            while current:
                path.insert(0, current.text(0))
                current = current.parent()

            # Emit signal with path
            if len(path) > 1:
                self.header_field_selected.emit(path[0], path[-1], item.text(1) if item.columnCount() > 1 else "")

    def _on_section_selection(self) -> None:
        """Handle section selection.

        Emits a signal when a section is selected with the section name
        and section data.

        Returns:
            None
        """
        if items := self.sections_table.selectedItems():
            row = items[0].row()
            if row < len(self.structure_data.get("sections", [])):
                section = self.structure_data["sections"][row]
                self.section_selected.emit(section.get("name", ""), section)

    def export_structure(self) -> None:
        """Export structure data.

        Displays a file save dialog and exports the structure data to JSON
        or formatted text format based on the selected file extension.

        Returns:
            None

        Raises:
            Exception: If the export operation fails (caught and displayed to user).
        """
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
        """Format structure data as readable text.

        Returns:
            Formatted text representation of the binary structure analysis.

        Raises:
            KeyError: If expected structure data keys are missing.
        """
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
