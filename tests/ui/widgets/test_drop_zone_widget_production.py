"""Production tests for Drop Zone Widget.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from intellicrack.handlers.pyqt6_handler import QApplication, QDragEnterEvent, QDropEvent, QMimeData, QUrl
from intellicrack.ui.widgets.drop_zone_widget import DropZoneWidget


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def widget(qapp: QApplication) -> DropZoneWidget:
    """Create drop zone widget for testing."""
    w = DropZoneWidget()
    yield w
    w.deleteLater()


@pytest.fixture
def temp_exe_file() -> Path:
    """Create temporary executable file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ\x90\x00")
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_dll_file() -> Path:
    """Create temporary DLL file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".dll", delete=False) as f:
        f.write(b"MZ\x90\x00")
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


def test_widget_initialization(widget: DropZoneWidget) -> None:
    """Widget initializes with default state."""
    assert widget.isEnabled()
    assert widget.acceptDrops()
    assert not widget.is_dragging
    assert widget.minimumHeight() >= 150


def test_widget_ui_components_exist(widget: DropZoneWidget) -> None:
    """Widget contains required UI components."""
    assert widget.label is not None
    assert widget.info_label is not None


def test_label_default_text(widget: DropZoneWidget) -> None:
    """Label shows correct default instruction text."""
    assert widget.label.text() == "Drop files here for analysis"


def test_info_label_shows_supported_formats(widget: DropZoneWidget) -> None:
    """Info label shows supported file formats."""
    info_text = widget.info_label.text()
    assert ".exe" in info_text
    assert ".dll" in info_text
    assert ".so" in info_text


def test_widget_minimum_height_set(widget: DropZoneWidget) -> None:
    """Widget has appropriate minimum height for drop zone."""
    assert widget.minimumHeight() >= 150


def test_widget_accepts_drops(widget: DropZoneWidget) -> None:
    """Widget is configured to accept drop events."""
    assert widget.acceptDrops()


def test_is_supported_file_exe(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """EXE files are recognized as supported."""
    assert widget._is_supported_file(str(temp_exe_file))


def test_is_supported_file_dll(widget: DropZoneWidget, temp_dll_file: Path) -> None:
    """DLL files are recognized as supported."""
    assert widget._is_supported_file(str(temp_dll_file))


def test_is_supported_file_so(widget: DropZoneWidget) -> None:
    """SO files are recognized as supported."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".so", delete=False) as f:
        f.write(b"\x7fELF")
        temp_path = Path(f.name)

    try:
        assert widget._is_supported_file(str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_is_supported_file_elf(widget: DropZoneWidget) -> None:
    """ELF files are recognized as supported."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".elf", delete=False) as f:
        f.write(b"\x7fELF")
        temp_path = Path(f.name)

    try:
        assert widget._is_supported_file(str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_is_supported_file_apk(widget: DropZoneWidget) -> None:
    """APK files are recognized as supported."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".apk", delete=False) as f:
        f.write(b"PK\x03\x04")
        temp_path = Path(f.name)

    try:
        assert widget._is_supported_file(str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_is_supported_file_case_insensitive(widget: DropZoneWidget) -> None:
    """File extension check is case insensitive."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".EXE", delete=False) as f:
        f.write(b"MZ\x90\x00")
        temp_path = Path(f.name)

    try:
        assert widget._is_supported_file(str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_is_supported_file_unsupported_extension(widget: DropZoneWidget) -> None:
    """Files with unsupported extensions are rejected."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test")
        temp_path = Path(f.name)

    try:
        assert not widget._is_supported_file(str(temp_path))
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_is_supported_file_nonexistent(widget: DropZoneWidget) -> None:
    """Nonexistent files are rejected."""
    assert not widget._is_supported_file("C:/nonexistent/file.exe")


def test_is_supported_file_all_extensions(widget: DropZoneWidget) -> None:
    """All documented supported extensions are recognized."""
    supported_extensions = [
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".elf",
        ".bin",
        ".sys",
        ".drv",
        ".ocx",
        ".app",
        ".apk",
        ".ipa",
        ".dex",
        ".jar",
        ".class",
        ".pyc",
        ".pyd",
        ".msi",
        ".rpm",
        ".deb",
        ".dmg",
        ".pkg",
    ]

    for ext in supported_extensions:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=ext, delete=False) as f:
            f.write(b"test")
            temp_path = Path(f.name)

        try:
            assert widget._is_supported_file(
                str(temp_path)
            ), f"Extension {ext} should be supported"
        finally:
            if temp_path.exists():
                temp_path.unlink()


def test_drag_enter_event_supported_file(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drag enter with supported file is accepted."""
    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    event = MagicMock(spec=QDragEnterEvent)
    event.mimeData.return_value = mime_data

    widget.dragEnterEvent(event)

    event.acceptProposedAction.assert_called_once()
    assert widget.is_dragging


def test_drag_enter_event_unsupported_file(widget: DropZoneWidget) -> None:
    """Drag enter with unsupported file is rejected."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test")
        temp_path = Path(f.name)

    try:
        mime_data = QMimeData()
        mime_data.setUrls([QUrl.fromLocalFile(str(temp_path))])

        event = MagicMock(spec=QDragEnterEvent)
        event.mimeData.return_value = mime_data

        widget.dragEnterEvent(event)

        event.ignore.assert_called_once()
        assert not widget.is_dragging
    finally:
        if temp_path.exists():
            temp_path.unlink()


def test_drag_enter_event_multiple_files_one_supported(
    widget: DropZoneWidget, temp_exe_file: Path
) -> None:
    """Drag enter with mixed files accepts if at least one is supported."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test")
        temp_txt = Path(f.name)

    try:
        mime_data = QMimeData()
        mime_data.setUrls(
            [QUrl.fromLocalFile(str(temp_txt)), QUrl.fromLocalFile(str(temp_exe_file))]
        )

        event = MagicMock(spec=QDragEnterEvent)
        event.mimeData.return_value = mime_data

        widget.dragEnterEvent(event)

        event.acceptProposedAction.assert_called_once()
        assert widget.is_dragging
    finally:
        if temp_txt.exists():
            temp_txt.unlink()


def test_drag_enter_event_no_urls(widget: DropZoneWidget) -> None:
    """Drag enter without URLs is rejected."""
    mime_data = QMimeData()

    event = MagicMock(spec=QDragEnterEvent)
    event.mimeData.return_value = mime_data

    widget.dragEnterEvent(event)

    event.ignore.assert_called_once()
    assert not widget.is_dragging


def test_drag_leave_event_resets_state(widget: DropZoneWidget) -> None:
    """Drag leave resets dragging state."""
    widget.is_dragging = True

    event = MagicMock(spec=QDragEnterEvent)
    widget.dragLeaveEvent(event)

    assert not widget.is_dragging


def test_drop_event_emits_signal(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drop event with supported file emits files_dropped signal."""
    signal_received = []

    def on_files_dropped(files: list[str]) -> None:
        signal_received.append(files)

    widget.files_dropped.connect(on_files_dropped)

    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    event = MagicMock(spec=QDropEvent)
    event.mimeData.return_value = mime_data

    widget.dropEvent(event)

    assert len(signal_received) == 1
    assert str(temp_exe_file) in signal_received[0]


def test_drop_event_filters_unsupported_files(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drop event filters out unsupported files from signal."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test")
        temp_txt = Path(f.name)

    try:
        signal_received = []

        def on_files_dropped(files: list[str]) -> None:
            signal_received.append(files)

        widget.files_dropped.connect(on_files_dropped)

        mime_data = QMimeData()
        mime_data.setUrls(
            [QUrl.fromLocalFile(str(temp_txt)), QUrl.fromLocalFile(str(temp_exe_file))]
        )

        event = MagicMock(spec=QDropEvent)
        event.mimeData.return_value = mime_data

        widget.dropEvent(event)

        assert len(signal_received) == 1
        assert str(temp_exe_file) in signal_received[0]
        assert str(temp_txt) not in signal_received[0]
    finally:
        if temp_txt.exists():
            temp_txt.unlink()


def test_drop_event_no_supported_files_ignores(widget: DropZoneWidget) -> None:
    """Drop event with no supported files ignores event."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("test")
        temp_txt = Path(f.name)

    try:
        signal_received = []

        def on_files_dropped(files: list[str]) -> None:
            signal_received.append(files)

        widget.files_dropped.connect(on_files_dropped)

        mime_data = QMimeData()
        mime_data.setUrls([QUrl.fromLocalFile(str(temp_txt))])

        event = MagicMock(spec=QDropEvent)
        event.mimeData.return_value = mime_data

        widget.dropEvent(event)

        event.ignore.assert_called_once()
        assert len(signal_received) == 0
    finally:
        if temp_txt.exists():
            temp_txt.unlink()


def test_drop_event_resets_dragging_state(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drop event resets dragging state."""
    widget.is_dragging = True

    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    event = MagicMock(spec=QDropEvent)
    event.mimeData.return_value = mime_data

    widget.dropEvent(event)

    assert not widget.is_dragging


def test_update_style_dragging_state(widget: DropZoneWidget) -> None:
    """Update style changes appearance when dragging."""
    widget.is_dragging = True
    widget.update_style()

    assert widget.label.text() == "Release to load files"
    assert "#e3f2fd" in widget.styleSheet() or "e3f2fd" in widget.styleSheet()


def test_update_style_normal_state(widget: DropZoneWidget) -> None:
    """Update style shows normal appearance when not dragging."""
    widget.is_dragging = False
    widget.update_style()

    assert widget.label.text() == "Drop files here for analysis"
    assert "#f5f5f5" in widget.styleSheet() or "f5f5f5" in widget.styleSheet()


def test_drag_enter_updates_style(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drag enter updates visual style."""
    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    event = MagicMock(spec=QDragEnterEvent)
    event.mimeData.return_value = mime_data

    widget.dragEnterEvent(event)

    assert "Release to load files" in widget.label.text()


def test_drag_leave_updates_style(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drag leave restores normal style."""
    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    enter_event = MagicMock(spec=QDragEnterEvent)
    enter_event.mimeData.return_value = mime_data
    widget.dragEnterEvent(enter_event)

    leave_event = MagicMock(spec=QDragEnterEvent)
    widget.dragLeaveEvent(leave_event)

    assert "Drop files here for analysis" in widget.label.text()


def test_label_center_aligned(widget: DropZoneWidget) -> None:
    """Main label is center aligned."""
    from intellicrack.handlers.pyqt6_handler import Qt

    assert widget.label.alignment() == Qt.AlignmentFlag.AlignCenter


def test_info_label_center_aligned(widget: DropZoneWidget) -> None:
    """Info label is center aligned."""
    from intellicrack.handlers.pyqt6_handler import Qt

    assert widget.info_label.alignment() == Qt.AlignmentFlag.AlignCenter


def test_label_font_size(widget: DropZoneWidget) -> None:
    """Main label has appropriate font size."""
    font = widget.label.font()
    assert font.pointSize() == 12


def test_drop_event_multiple_files_emits_all_supported(
    widget: DropZoneWidget, temp_exe_file: Path, temp_dll_file: Path
) -> None:
    """Drop event with multiple supported files emits all."""
    signal_received = []

    def on_files_dropped(files: list[str]) -> None:
        signal_received.append(files)

    widget.files_dropped.connect(on_files_dropped)

    mime_data = QMimeData()
    mime_data.setUrls(
        [QUrl.fromLocalFile(str(temp_exe_file)), QUrl.fromLocalFile(str(temp_dll_file))]
    )

    event = MagicMock(spec=QDropEvent)
    event.mimeData.return_value = mime_data

    widget.dropEvent(event)

    assert len(signal_received) == 1
    assert len(signal_received[0]) == 2
    assert str(temp_exe_file) in signal_received[0]
    assert str(temp_dll_file) in signal_received[0]


def test_paint_event_draws_highlight_when_dragging(widget: DropZoneWidget) -> None:
    """Paint event draws visual highlight during drag."""
    widget.is_dragging = True

    from intellicrack.handlers.pyqt6_handler import QPaintEvent

    paint_event = QPaintEvent(widget.rect())

    with patch("intellicrack.ui.widgets.drop_zone_widget.QPainter") as mock_painter:
        widget.paintEvent(paint_event)

        mock_painter.assert_called()


def test_drop_event_accepts_proposed_action(widget: DropZoneWidget, temp_exe_file: Path) -> None:
    """Drop event accepts proposed action for supported files."""
    mime_data = QMimeData()
    mime_data.setUrls([QUrl.fromLocalFile(str(temp_exe_file))])

    event = MagicMock(spec=QDropEvent)
    event.mimeData.return_value = mime_data

    widget.dropEvent(event)

    event.acceptProposedAction.assert_called_once()


def test_widget_layout_has_proper_margins(widget: DropZoneWidget) -> None:
    """Widget layout has appropriate margins."""
    layout = widget.layout()
    margins = layout.contentsMargins()

    assert margins.left() == 20
    assert margins.right() == 20
    assert margins.top() == 20
    assert margins.bottom() == 20


def test_info_label_has_color_style(widget: DropZoneWidget) -> None:
    """Info label has color styling applied."""
    style = widget.info_label.styleSheet()
    assert "color" in style.lower()
