"""PE Structure Tree Model for Hex Viewer Integration.

Provides a QAbstractItemModel adapter for PEFileModel to display PE structures
in a tree view with navigation capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, Qt, pyqtSignal

from .pe_file_model import CertificateInfo, FileStructure, PEFileModel, SectionInfo


class PEStructureItem:
    """Tree item representing a PE structure element."""

    def __init__(
        self,
        data: FileStructure | SectionInfo | str,
        parent: "PEStructureItem | None" = None,
    ) -> None:
        """Initialize PE structure item with hierarchical data representation."""
        self.parent_item = parent
        self.item_data = data
        self.child_items: list[PEStructureItem] = []

    def append_child(self, item: "PEStructureItem") -> None:
        """Add a child item."""
        self.child_items.append(item)

    def child(self, row: int) -> "PEStructureItem | None":
        """Get child at row."""
        if 0 <= row < len(self.child_items):
            return self.child_items[row]
        return None

    def child_count(self) -> int:
        """Get number of children."""
        return len(self.child_items)

    def column_count(self) -> int:
        """Get number of columns."""
        return 3  # Name, Offset, Size

    def data(self, column: int) -> object:
        """Get data for column."""
        if isinstance(self.item_data, str):
            # Root node or category
            return self.item_data if column == 0 else ""

        if isinstance(self.item_data, FileStructure):
            if column == 0:
                return self.item_data.name
            if column == 1:
                return f"0x{self.item_data.offset:X}"
            if column == 2:
                return f"0x{self.item_data.size:X}"

        elif isinstance(self.item_data, SectionInfo):
            if column == 0:
                return self.item_data.name
            if column == 1:
                return f"0x{self.item_data.raw_offset:X}"
            if column == 2:
                return f"0x{self.item_data.raw_size:X}"

        return ""

    def parent(self) -> "PEStructureItem | None":
        """Get parent item."""
        return self.parent_item

    def row(self) -> int:
        """Get row number in parent."""
        if self.parent_item:
            return self.parent_item.child_items.index(self)
        return 0


class PEStructureModel(QAbstractItemModel):
    """QAbstractItemModel for PE structure tree display."""

    # Signals
    #: offset, size (type: int, int)
    structure_selected = pyqtSignal(int, int)
    #: RVA address (type: int)
    rva_selected = pyqtSignal(int)

    def __init__(
        self,
        pe_model: PEFileModel | None = None,
        parent: object | None = None,
    ) -> None:
        """Initialize PE structure model with optional PE file data for tree representation."""
        super().__init__(parent)
        self.pe_model = pe_model
        self.root_item = PEStructureItem("PE Structure")

        if self.pe_model:
            self.setup_model_data()

    def set_pe_model(self, pe_model: PEFileModel) -> None:
        """Set the PE model and rebuild tree."""
        self.beginResetModel()
        self.pe_model = pe_model
        self.root_item = PEStructureItem("PE Structure")
        self.setup_model_data()
        self.endResetModel()

    def _add_file_info_section(self) -> None:
        """Add file information section to the tree."""
        file_info = PEStructureItem("File Information", self.root_item)
        self.root_item.append_child(file_info)

        info = self.pe_model.get_file_info()
        for key, value in info.items():
            if key not in ["file_path", "parsed"]:
                info_item = PEStructureItem(f"{key}: {value}", file_info)
                file_info.append_child(info_item)

    def _add_headers_section(self) -> None:
        """Add headers section to the tree."""
        headers = PEStructureItem("Headers", self.root_item)
        self.root_item.append_child(headers)

        for structure in self.pe_model.get_structures():
            if structure.structure_type == "header":
                header_item = PEStructureItem(structure, headers)
                headers.append_child(header_item)

                # Add properties as children
                for prop_name, prop_value in structure.properties.items():
                    prop_item = PEStructureItem(f"{prop_name}: {prop_value}", header_item)
                    header_item.append_child(prop_item)

    def _add_sections_section(self) -> None:
        """Add sections information to the tree."""
        sections = PEStructureItem("Sections", self.root_item)
        self.root_item.append_child(sections)

        for section in self.pe_model.get_sections():
            section_item = PEStructureItem(section, sections)
            sections.append_child(section_item)

            # Add section properties
            properties = [
                f"Virtual Address: 0x{section.virtual_address:X}",
                f"Virtual Size: 0x{section.virtual_size:X}",
                f"Raw Offset: 0x{section.raw_offset:X}",
                f"Raw Size: 0x{section.raw_size:X}",
                f"Characteristics: 0x{section.characteristics:X}",
                f"Executable: {section.is_executable}",
                f"Writable: {section.is_writable}",
                f"Readable: {section.is_readable}",
            ]

            if section.entropy is not None:
                properties.append(f"Entropy: {section.entropy:.2f}")

            for prop in properties:
                prop_item = PEStructureItem(prop, section_item)
                section_item.append_child(prop_item)

    def _add_data_directories_section(self) -> None:
        """Add data directories section to the tree."""
        directories = PEStructureItem("Data Directories", self.root_item)
        self.root_item.append_child(directories)

        for structure in self.pe_model.get_structures():
            if structure.structure_type == "directory":
                dir_item = PEStructureItem(structure, directories)
                directories.append_child(dir_item)

                # Add directory properties
                for prop_name, prop_value in structure.properties.items():
                    prop_item = PEStructureItem(f"{prop_name}: {prop_value}", dir_item)
                    dir_item.append_child(prop_item)

    def _add_imports_section(self) -> None:
        """Add imports section to the tree."""
        imports = self.pe_model.get_imports()
        if not imports:
            return

        imports_root = PEStructureItem("Imports", self.root_item)
        self.root_item.append_child(imports_root)

        # Group by DLL
        dll_groups = {}
        for imp in imports:
            if imp.dll_name not in dll_groups:
                dll_groups[imp.dll_name] = []
            dll_groups[imp.dll_name].append(imp)

        for dll_name, dll_imports in dll_groups.items():
            dll_item = PEStructureItem(f"{dll_name} ({len(dll_imports)} functions)", imports_root)
            imports_root.append_child(dll_item)

            for imp in dll_imports[:20]:  # Limit to first 20 for performance
                func_text = f"{imp.function_name} @ 0x{imp.address:X}"
                if imp.ordinal:
                    func_text += f" (Ordinal: {imp.ordinal})"
                func_item = PEStructureItem(func_text, dll_item)
                dll_item.append_child(func_item)

            if len(dll_imports) > 20:
                more_item = PEStructureItem(f"... and {len(dll_imports) - 20} more", dll_item)
                dll_item.append_child(more_item)

    def _add_exports_section(self) -> None:
        """Add exports section to the tree."""
        exports = self.pe_model.get_exports()
        if not exports:
            return

        exports_root = PEStructureItem("Exports", self.root_item)
        self.root_item.append_child(exports_root)

        for exp in exports[:50]:  # Limit for performance
            exp_text = f"{exp.function_name} @ 0x{exp.address:X} (Ordinal: {exp.ordinal})"
            if exp.forwarder:
                exp_text += f" -> {exp.forwarder}"
            exp_item = PEStructureItem(exp_text, exports_root)
            exports_root.append_child(exp_item)

        if len(exports) > 50:
            more_item = PEStructureItem(f"... and {len(exports) - 50} more", exports_root)
            exports_root.append_child(more_item)

    def _add_certificate_details(
        self,
        signing_cert: object,
        certificates_root: PEStructureItem,
    ) -> None:
        """Add certificate details to the tree."""
        cert_info = "Signing Certificate"
        if signing_cert.subject:
            # Extract CN from subject
            subject_parts = signing_cert.subject.split(",")
            cn_part = next(
                (part.strip() for part in subject_parts if part.strip().startswith("CN=")),
                None,
            )
            if cn_part:
                cert_info = f"{cert_info} - {cn_part[3:]}"  # Remove 'CN=' prefix

        cert_item = PEStructureItem(cert_info, certificates_root)
        certificates_root.append_child(cert_item)

        # Certificate details
        details = [
            f"Subject: {signing_cert.subject}",
            f"Issuer: {signing_cert.issuer}",
            f"Serial: {signing_cert.serial_number}",
            f"Valid From: {signing_cert.not_before.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Valid To: {signing_cert.not_after.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Algorithm: {signing_cert.signature_algorithm}",
            f"Key: {signing_cert.public_key_algorithm} {signing_cert.public_key_size} bits",
            f"SHA1: {signing_cert.fingerprint_sha1}",
            f"Valid: {'Yes' if signing_cert.is_valid else 'No'}",
            f"Code Signing: {'Yes' if signing_cert.is_code_signing else 'No'}",
            f"Self-Signed: {'Yes' if signing_cert.is_self_signed else 'No'}",
        ]

        for detail in details:
            detail_item = PEStructureItem(detail, cert_item)
            cert_item.append_child(detail_item)

    def _add_certificate_chain(
        self,
        certificates: CertificateInfo,
        certificates_root: PEStructureItem,
    ) -> None:
        """Add certificate chain information to the tree."""
        if len(certificates.certificates) <= 1:
            return

        chain_item = PEStructureItem(
            f"Certificate Chain ({len(certificates.certificates)} certificates)",
            certificates_root,
        )
        certificates_root.append_child(chain_item)

        for i, cert in enumerate(certificates.certificates[1:], 1):
            cert_name = f"Certificate {i}"
            # Try to get CN from subject
            if cert.subject:
                subject_parts = cert.subject.split(",")
                cn_part = next(
                    (part.strip() for part in subject_parts if part.strip().startswith("CN=")),
                    None,
                )
                if cn_part:
                    cert_name = f"{cert_name} - {cn_part[3:]}"

            chain_cert_item = PEStructureItem(cert_name, chain_item)
            chain_item.append_child(chain_cert_item)

    def _add_certificates_section(self) -> None:
        """Add certificates section to the tree."""
        certificates = self.pe_model.get_certificates()
        if not certificates or not certificates.is_signed:
            return

        certificates_root = PEStructureItem("Digital Certificates", self.root_item)
        self.root_item.append_child(certificates_root)

        # Signing information
        signing_cert = certificates.signing_certificate
        if signing_cert:
            self._add_certificate_details(signing_cert, certificates_root)

        # Trust status
        trust_item = PEStructureItem(f"Trust Status: {certificates.trust_status}", certificates_root)
        certificates_root.append_child(trust_item)

        # Additional certificates in chain
        self._add_certificate_chain(certificates, certificates_root)

    def setup_model_data(self) -> None:
        """Build the tree structure from PE model."""
        if not self.pe_model:
            return

        # Add all sections
        self._add_file_info_section()
        self._add_headers_section()
        self._add_sections_section()
        self._add_data_directories_section()
        self._add_imports_section()
        self._add_exports_section()
        self._add_certificates_section()

    def columnCount(self, parent: QModelIndex = None) -> int:
        """Return number of columns."""
        if parent is None:
            parent = QModelIndex()
        return self.root_item.column_count()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> object:
        """Return data for index and role."""
        if not index.isValid():
            return None

        item = index.internalPointer()

        if role == Qt.ItemDataRole.DisplayRole:
            return item.data(index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            if isinstance(item.item_data, FileStructure):
                return f"{item.item_data.description}\nOffset: 0x{item.item_data.offset:X}\nSize: 0x{item.item_data.size:X}"
            if isinstance(item.item_data, SectionInfo):
                tooltip = f"Section: {item.item_data.name}\n"
                tooltip += f"Virtual Address: 0x{item.item_data.virtual_address:X}\n"
                tooltip += f"Raw Offset: 0x{item.item_data.raw_offset:X}\n"
                tooltip += f"Characteristics: 0x{item.item_data.characteristics:X}\n"
                tooltip += "Permissions: "
                perms = []
                if item.item_data.is_readable:
                    perms.append("R")
                if item.item_data.is_writable:
                    perms.append("W")
                if item.item_data.is_executable:
                    perms.append("X")
                tooltip += "".join(perms) if perms else "None"
                return tooltip

        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        """Return item flags."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        """Return header data."""
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if section == 0:
                return "Name"
            if section == 1:
                return "Offset"
            if section == 2:
                return "Size"

        return None

    def index(self, row: int, column: int, parent: QModelIndex = None) -> QModelIndex:
        """Create index for row, column under parent."""
        if parent is None:
            parent = QModelIndex()
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)
        if child_item:
            return self.createIndex(row, column, child_item)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        """Return parent of index."""
        if not index.isValid():
            return QModelIndex()

        child_item = index.internalPointer()
        parent_item = child_item.parent()

        if parent_item == self.root_item:
            return QModelIndex()

        return self.createIndex(parent_item.row(), 0, parent_item)

    def rowCount(self, parent: QModelIndex = None) -> int:
        """Return number of rows under parent."""
        if parent is None:
            parent = QModelIndex()
        if parent.column() > 0:
            return 0

        if not parent.isValid():
            parent_item = self.root_item
        else:
            parent_item = parent.internalPointer()

        return parent_item.child_count()

    def get_item_offset_and_size(self, index: QModelIndex) -> tuple[int | None, int | None]:
        """Get file offset and size for item at index."""
        if not index.isValid():
            return None, None

        item = index.internalPointer()

        if isinstance(item.item_data, FileStructure):
            return item.item_data.offset, item.item_data.size
        if isinstance(item.item_data, SectionInfo):
            return item.item_data.raw_offset, item.item_data.raw_size

        return None, None

    def get_item_rva(self, index: QModelIndex) -> int | None:
        """Get RVA for item at index."""
        if not index.isValid():
            return None

        item = index.internalPointer()

        if isinstance(item.item_data, SectionInfo):
            return item.item_data.virtual_address
        if isinstance(item.item_data, FileStructure):
            # Convert file offset to RVA if possible
            if self.pe_model:
                return self.pe_model.offset_to_rva(item.item_data.offset)

        return None
