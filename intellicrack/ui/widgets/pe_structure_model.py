"""PE Structure Tree Model for Hex Viewer Integration.

Provides a QAbstractItemModel adapter for PEFileModel to display PE structures
in a tree view with navigation capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any

from PyQt6.QtCore import QAbstractItemModel, QModelIndex, QObject, Qt, pyqtSignal

from ...utils.binary.certificate_extractor import CertificateInfo, CodeSigningInfo
from .pe_file_model import FileStructure, PEFileModel, SectionInfo


class PEStructureItem:
    """Tree item representing a PE structure element."""

    def __init__(
        self,
        data: FileStructure | SectionInfo | str,
        parent: "PEStructureItem | None" = None,
    ) -> None:
        """Initialize PE structure item with hierarchical data representation.

        Args:
            data: The data to store in this tree item. Can be a FileStructure,
                SectionInfo, or string label.
            parent: The parent PEStructureItem, or None if this is a root item.
        """
        self.parent_item = parent
        self.item_data = data
        self.child_items: list[PEStructureItem] = []

    def append_child(self, item: "PEStructureItem") -> None:
        """Add a child item to this node's children.

        Args:
            item: The PEStructureItem to append as a child.
        """
        self.child_items.append(item)

    def child(self, row: int) -> "PEStructureItem | None":
        """Get child at the specified row index.

        Args:
            row: The zero-based row index of the child to retrieve.

        Returns:
            The PEStructureItem at the specified row, or None if the row index
            is out of bounds.
        """
        return self.child_items[row] if 0 <= row < len(self.child_items) else None

    def child_count(self) -> int:
        """Get the number of child items.

        Returns:
            The count of child items in this node's children list.
        """
        return len(self.child_items)

    def column_count(self) -> int:
        """Get the number of columns in the tree model.

        Returns:
            The number of columns (3: Name, Offset, Size).
        """
        return 3

    def data(self, column: int) -> str:
        """Get the data for the specified column.

        Args:
            column: The column index (0=Name, 1=Offset, 2=Size).

        Returns:
            The data string for the specified column, or an empty string if the
            column index is invalid or data is not available.
        """
        if isinstance(self.item_data, str):
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
        """Get the parent item of this node.

        Returns:
            The parent PEStructureItem, or None if this is a root item.
        """
        return self.parent_item

    def row(self) -> int:
        """Get the row index of this item within its parent's children.

        Returns:
            The zero-based row index, or 0 if this is a root item with no parent.
        """
        return self.parent_item.child_items.index(self) if self.parent_item else 0


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
        parent: QObject | None = None,
    ) -> None:
        """Initialize PE structure model with optional PE file data for tree representation.

        Args:
            pe_model: The PEFileModel containing PE binary data to be displayed in the tree,
                or None to create an empty model.
            parent: The parent QObject for Qt parent-child relationships, or None.
        """
        super().__init__(parent)
        self.pe_model = pe_model
        self.root_item = PEStructureItem("PE Structure")

        if self.pe_model:
            self.setup_model_data()

    def set_pe_model(self, pe_model: PEFileModel) -> None:
        """Set the PE model and rebuild the tree structure.

        Args:
            pe_model: The new PEFileModel to display in the tree.
        """
        self.beginResetModel()
        self.pe_model = pe_model
        self.root_item = PEStructureItem("PE Structure")
        self.setup_model_data()
        self.endResetModel()

    def _add_file_info_section(self) -> None:
        """Add file information section to the tree.

        Populates the tree with file metadata including size, timestamps, and
        other header information from the PE file model.
        """
        if not self.pe_model:
            return

        file_info = PEStructureItem("File Information", self.root_item)
        self.root_item.append_child(file_info)

        info = self.pe_model.get_file_info()
        for key, value in info.items():
            if key not in ["file_path", "parsed"]:
                info_item = PEStructureItem(f"{key}: {value}", file_info)
                file_info.append_child(info_item)

    def _add_headers_section(self) -> None:
        """Add headers section to the tree.

        Populates the tree with PE header structures including DOS header, NT header,
        and other PE headers with their properties and field values.
        """
        if not self.pe_model:
            return

        headers = PEStructureItem("Headers", self.root_item)
        self.root_item.append_child(headers)

        for structure in self.pe_model.get_structures():
            if structure.structure_type == "header":
                header_item = PEStructureItem(structure, headers)
                headers.append_child(header_item)

                for prop_name, prop_value in structure.properties.items():
                    prop_item = PEStructureItem(f"{prop_name}: {prop_value}", header_item)
                    header_item.append_child(prop_item)

    def _add_sections_section(self) -> None:
        """Add sections information to the tree.

        Populates the tree with all PE sections including their virtual/raw addresses,
        sizes, characteristics, and permissions (readable/writable/executable).
        """
        if not self.pe_model:
            return

        sections = PEStructureItem("Sections", self.root_item)
        self.root_item.append_child(sections)

        for section in self.pe_model.get_sections():
            section_item = PEStructureItem(section, sections)
            sections.append_child(section_item)

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
        """Add data directories section to the tree.

        Populates the tree with PE data directory entries such as Import Table,
        Export Table, Resource Directory, and other standard PE directories.
        """
        if not self.pe_model:
            return

        directories = PEStructureItem("Data Directories", self.root_item)
        self.root_item.append_child(directories)

        for structure in self.pe_model.get_structures():
            if structure.structure_type == "directory":
                dir_item = PEStructureItem(structure, directories)
                directories.append_child(dir_item)

                for prop_name, prop_value in structure.properties.items():
                    prop_item = PEStructureItem(f"{prop_name}: {prop_value}", dir_item)
                    dir_item.append_child(prop_item)

    def _add_imports_section(self) -> None:
        """Add imports section to the tree.

        Populates the tree with imported functions grouped by DLL. Shows the first
        20 imports per DLL for performance, with a count indicator if more exist.
        """
        if not self.pe_model:
            return

        imports = self.pe_model.get_imports()
        if not imports:
            return

        imports_root = PEStructureItem("Imports", self.root_item)
        self.root_item.append_child(imports_root)

        dll_groups: dict[str, list[Any]] = {}
        for imp in imports:
            if imp.dll_name not in dll_groups:
                dll_groups[imp.dll_name] = []
            dll_groups[imp.dll_name].append(imp)

        for dll_name, dll_imports in dll_groups.items():
            dll_item = PEStructureItem(f"{dll_name} ({len(dll_imports)} functions)", imports_root)
            imports_root.append_child(dll_item)

            for imp in dll_imports[:20]:
                func_text = f"{imp.function_name} @ 0x{imp.address:X}"
                if imp.ordinal:
                    func_text += f" (Ordinal: {imp.ordinal})"
                func_item = PEStructureItem(func_text, dll_item)
                dll_item.append_child(func_item)

            if len(dll_imports) > 20:
                more_item = PEStructureItem(f"... and {len(dll_imports) - 20} more", dll_item)
                dll_item.append_child(more_item)

    def _add_exports_section(self) -> None:
        """Add exports section to the tree.

        Populates the tree with exported functions showing function names, addresses,
        ordinal values, and forward references. Limited to first 50 for performance.
        """
        if not self.pe_model:
            return

        exports = self.pe_model.get_exports()
        if not exports:
            return

        exports_root = PEStructureItem("Exports", self.root_item)
        self.root_item.append_child(exports_root)

        for exp in exports[:50]:
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
        signing_cert: CertificateInfo,
        certificates_root: PEStructureItem,
    ) -> None:
        """Add certificate details to the tree.

        Args:
            signing_cert: The certificate information containing subject, issuer,
                validity dates, and other certificate properties.
            certificates_root: The parent tree item under which certificate details
                will be added.
        """
        cert_info = "Signing Certificate"
        if signing_cert.subject:
            subject_parts = signing_cert.subject.split(",")
            if cn_part := next(
                (part.strip() for part in subject_parts if part.strip().startswith("CN=")),
                None,
            ):
                cert_info = f"{cert_info} - {cn_part[3:]}"

        cert_item = PEStructureItem(cert_info, certificates_root)
        certificates_root.append_child(cert_item)

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
        certificates: CodeSigningInfo,
        certificates_root: PEStructureItem,
    ) -> None:
        """Add certificate chain information to the tree.

        Args:
            certificates: The CodeSigningInfo containing the chain of certificates
                used to sign the PE file.
            certificates_root: The parent tree item under which the certificate chain
                will be added.
        """
        if len(certificates.certificates) <= 1:
            return

        chain_item = PEStructureItem(
            f"Certificate Chain ({len(certificates.certificates)} certificates)",
            certificates_root,
        )
        certificates_root.append_child(chain_item)

        for i, cert in enumerate(certificates.certificates[1:], 1):
            cert_name = f"Certificate {i}"
            if cert.subject:
                subject_parts = cert.subject.split(",")
                if cn_part := next(
                    (part.strip() for part in subject_parts if part.strip().startswith("CN=")),
                    None,
                ):
                    cert_name = f"{cert_name} - {cn_part[3:]}"

            chain_cert_item = PEStructureItem(cert_name, chain_item)
            chain_item.append_child(chain_cert_item)

    def _add_certificates_section(self) -> None:
        """Add certificates section to the tree.

        Populates the tree with digital certificate information including the signing
        certificate details, trust status, and certificate chain.
        """
        if not self.pe_model:
            return

        certificates = self.pe_model.get_certificates()
        if not certificates or not certificates.is_signed:
            return

        certificates_root = PEStructureItem("Digital Certificates", self.root_item)
        self.root_item.append_child(certificates_root)

        if signing_cert := certificates.signing_certificate:
            self._add_certificate_details(signing_cert, certificates_root)

        trust_item = PEStructureItem(f"Trust Status: {certificates.trust_status}", certificates_root)
        certificates_root.append_child(trust_item)

        self._add_certificate_chain(certificates, certificates_root)

    def setup_model_data(self) -> None:
        """Build the tree structure from PE model.

        Populates the root item with all PE structure sections including file info,
        headers, sections, directories, imports, exports, and certificates.
        """
        if not self.pe_model:
            return

        self._add_file_info_section()
        self._add_headers_section()
        self._add_sections_section()
        self._add_data_directories_section()
        self._add_imports_section()
        self._add_exports_section()
        self._add_certificates_section()

    def columnCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of columns.

        Args:
            parent: The parent QModelIndex (unused in tree model).

        Returns:
            The number of columns in the tree model (3).
        """
        if parent is None or not parent.isValid():
            return self.root_item.column_count()
        return self.root_item.column_count()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> str | None:
        """Return data for index and role.

        Args:
            index: The QModelIndex of the item to retrieve data for.
            role: The data role being requested (DisplayRole or ToolTipRole).

        Returns:
            The data string for the specified index and role, or None if the index
            is invalid or role is not supported.
        """
        if not index.isValid():
            return None

        item_ptr = index.internalPointer()
        if not isinstance(item_ptr, PEStructureItem):
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return item_ptr.data(index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            if isinstance(item_ptr.item_data, FileStructure):
                return f"{item_ptr.item_data.description}\nOffset: 0x{item_ptr.item_data.offset:X}\nSize: 0x{item_ptr.item_data.size:X}"
            if isinstance(item_ptr.item_data, SectionInfo):
                tooltip = f"Section: {item_ptr.item_data.name}\n"
                tooltip += f"Virtual Address: 0x{item_ptr.item_data.virtual_address:X}\n"
                tooltip += f"Raw Offset: 0x{item_ptr.item_data.raw_offset:X}\n"
                tooltip += f"Characteristics: 0x{item_ptr.item_data.characteristics:X}\n"
                tooltip += "Permissions: "
                perms: list[str] = []
                if item_ptr.item_data.is_readable:
                    perms.append("R")
                if item_ptr.item_data.is_writable:
                    perms.append("W")
                if item_ptr.item_data.is_executable:
                    perms.append("X")
                tooltip += "".join(perms) if perms else "None"
                return tooltip

        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        """Return item flags.

        Args:
            index: The QModelIndex of the item to get flags for.

        Returns:
            Item flags indicating the item is enabled and selectable, or NoItemFlags
            if the index is invalid.
        """
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags

        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> str | None:
        """Return header data.

        Args:
            section: The column section index.
            orientation: The orientation of the header (Horizontal or Vertical).
            role: The data role being requested.

        Returns:
            The header label string for horizontal headers ("Name", "Offset", "Size"),
            or None for vertical headers or unsupported roles.
        """
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if section == 0:
                return "Name"
            if section == 1:
                return "Offset"
            if section == 2:
                return "Size"

        return None

    def index(self, row: int, column: int, parent: QModelIndex | None = None) -> QModelIndex:
        """Create index for row, column under parent.

        Args:
            row: The row number in the parent item.
            column: The column number.
            parent: The parent QModelIndex, or None for the root item.

        Returns:
            A QModelIndex for the specified row and column, or an invalid QModelIndex
            if the index is out of bounds.
        """
        if parent is None:
            parent = QModelIndex()
        if not self.hasIndex(row, column, parent):
            return QModelIndex()

        parent_item_ptr = parent.internalPointer() if parent.isValid() else self.root_item
        if not isinstance(parent_item_ptr, PEStructureItem):
            parent_item_ptr = self.root_item

        if child_item := parent_item_ptr.child(row):
            return self.createIndex(row, column, child_item)
        return QModelIndex()

    def parent(self, index: QModelIndex) -> QModelIndex:
        """Return parent of index.

        Args:
            index: The QModelIndex of the child item.

        Returns:
            A QModelIndex for the parent item, or an invalid QModelIndex if the item
            is at the root level or the index is invalid.
        """
        if not index.isValid():
            return QModelIndex()

        child_item_ptr = index.internalPointer()
        if not isinstance(child_item_ptr, PEStructureItem):
            return QModelIndex()

        parent_item = child_item_ptr.parent()
        if parent_item is None or parent_item == self.root_item:
            return QModelIndex()

        return self.createIndex(parent_item.row(), 0, parent_item)

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        """Return number of rows under parent.

        Args:
            parent: The parent QModelIndex, or None for the root item.

        Returns:
            The number of child rows under the parent item.
        """
        if parent is None:
            parent = QModelIndex()
        if parent.column() > 0:
            return 0

        parent_item_ptr = parent.internalPointer() if parent.isValid() else self.root_item
        if not isinstance(parent_item_ptr, PEStructureItem):
            parent_item_ptr = self.root_item

        return parent_item_ptr.child_count()

    def get_item_offset_and_size(self, index: QModelIndex) -> tuple[int | None, int | None]:
        """Get file offset and size for item at index.

        Args:
            index: The QModelIndex of the item to retrieve offset and size for.

        Returns:
            A tuple of (offset, size) for the item, or (None, None) if the index
            is invalid or the item does not have offset/size data.
        """
        if not index.isValid():
            return None, None

        item_ptr = index.internalPointer()
        if not isinstance(item_ptr, PEStructureItem):
            return None, None

        if isinstance(item_ptr.item_data, FileStructure):
            return item_ptr.item_data.offset, item_ptr.item_data.size
        if isinstance(item_ptr.item_data, SectionInfo):
            return item_ptr.item_data.raw_offset, item_ptr.item_data.raw_size

        return None, None

    def get_item_rva(self, index: QModelIndex) -> int | None:
        """Get RVA for item at index.

        Args:
            index: The QModelIndex of the item to retrieve RVA for.

        Returns:
            The relative virtual address (RVA) for the item, or None if the index
            is invalid, the item does not have RVA data, or the PE model is not available.
        """
        if not index.isValid():
            return None

        item_ptr = index.internalPointer()
        if not isinstance(item_ptr, PEStructureItem):
            return None

        if isinstance(item_ptr.item_data, SectionInfo):
            return item_ptr.item_data.virtual_address
        if isinstance(item_ptr.item_data, FileStructure) and self.pe_model:
            return self.pe_model.offset_to_rva(item_ptr.item_data.offset)

        return None
