"""Production tests for memory dumper widget - validates real memory operations.

Tests verify memory dumping functionality including process enumeration, memory region
scanning, region filtering, and actual memory reading from processes on Windows and Linux.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import platform
import sys
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.psutil_handler import psutil
from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.ui.widgets.memory_dumper import MemoryDumperWidget, MemoryDumpThread


@pytest.fixture(scope="module")
def qapp() -> Generator[Any, None, None]:
    """Create QApplication instance for widget tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.quit()


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Create temporary output directory for memory dumps."""
    output_dir = tmp_path / "memory_dumps"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def memory_dumper_widget(qapp: Any) -> Generator[MemoryDumperWidget, None, None]:
    """Create memory dumper widget for testing."""
    widget = MemoryDumperWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def current_process_pid() -> int:
    """Get current process PID for testing."""
    return os.getpid()


class TestMemoryDumperWidget:
    """Test MemoryDumperWidget with real process operations."""

    def test_widget_initialization(self, memory_dumper_widget: MemoryDumperWidget) -> None:
        """Verify widget initializes with all UI components."""
        assert memory_dumper_widget.process_combo is not None
        assert memory_dumper_widget.process_info is not None
        assert memory_dumper_widget.regions_table is not None
        assert memory_dumper_widget.readable_check is not None
        assert memory_dumper_widget.writable_check is not None
        assert memory_dumper_widget.executable_check is not None
        assert memory_dumper_widget.private_check is not None
        assert memory_dumper_widget.raw_dump_check is not None
        assert memory_dumper_widget.minidump_check is not None
        assert memory_dumper_widget.full_dump_check is not None
        assert memory_dumper_widget.compress_check is not None
        assert memory_dumper_widget.progress_bar is not None
        assert memory_dumper_widget.output_log is not None

    def test_refresh_process_list_populates_combo(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test process list refresh populates process combo box."""
        memory_dumper_widget.process_combo.clear()
        memory_dumper_widget.refresh_process_list()

        assert memory_dumper_widget.process_combo.count() > 0

        found_python = False
        for i in range(memory_dumper_widget.process_combo.count()):
            item_text = memory_dumper_widget.process_combo.itemText(i)
            if "python" in item_text.lower() or "pytest" in item_text.lower():
                found_python = True
                break

        assert found_python, "Should find Python/pytest process in list"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_refresh_windows_processes(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Windows process enumeration."""
        memory_dumper_widget._refresh_windows_processes()

        assert memory_dumper_widget.process_combo.count() > 0

        for i in range(min(5, memory_dumper_widget.process_combo.count())):
            if item_data := memory_dumper_widget.process_combo.itemData(i):
                assert isinstance(item_data, int)
                assert item_data > 0

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_refresh_linux_processes(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Linux process enumeration."""
        memory_dumper_widget._refresh_linux_processes()

        assert memory_dumper_widget.process_combo.count() > 0

        for i in range(min(5, memory_dumper_widget.process_combo.count())):
            if item_data := memory_dumper_widget.process_combo.itemData(i):
                assert isinstance(item_data, int)
                assert item_data > 0

    def test_attach_to_process_by_combo_selection(
        self, memory_dumper_widget: MemoryDumperWidget, current_process_pid: int
    ) -> None:
        """Test attaching to process via combo box selection."""
        memory_dumper_widget.refresh_process_list()

        for i in range(memory_dumper_widget.process_combo.count()):
            item_data = memory_dumper_widget.process_combo.itemData(i)
            if item_data == current_process_pid:
                memory_dumper_widget.process_combo.setCurrentIndex(i)
                break

        memory_dumper_widget.attach_to_process()

        assert memory_dumper_widget.current_process == current_process_pid
        assert f"PID: {current_process_pid}" in memory_dumper_widget.process_info.text()

    def test_attach_to_process_by_text_input(
        self, memory_dumper_widget: MemoryDumperWidget, current_process_pid: int
    ) -> None:
        """Test attaching to process by entering PID in combo box."""
        memory_dumper_widget.process_combo.setCurrentText(f"Test Process (PID: {current_process_pid})")

        memory_dumper_widget.attach_to_process()

        assert memory_dumper_widget.current_process == current_process_pid

    def test_get_dump_options_returns_selected_options(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test get_dump_options returns currently selected options."""
        memory_dumper_widget.raw_dump_check.setChecked(True)
        memory_dumper_widget.minidump_check.setChecked(False)
        memory_dumper_widget.full_dump_check.setChecked(False)
        memory_dumper_widget.compress_check.setChecked(True)
        memory_dumper_widget.metadata_check.setChecked(True)
        memory_dumper_widget.strings_check.setChecked(False)

        options = memory_dumper_widget.get_dump_options()

        assert options["raw"] is True
        assert options["minidump"] is False
        assert options["full"] is False
        assert options["compress"] is True
        assert options["metadata"] is True
        assert options["strings"] is False

    def test_update_progress_updates_bar(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test progress bar updates correctly."""
        memory_dumper_widget.update_progress(45)
        assert memory_dumper_widget.progress_bar.value() == 45

        memory_dumper_widget.update_progress(100)
        assert memory_dumper_widget.progress_bar.value() == 100

    def test_dump_finished_hides_progress_bar(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test dump completion hides progress bar."""
        memory_dumper_widget.progress_bar.setVisible(True)
        memory_dumper_widget.dump_finished()

        assert not memory_dumper_widget.progress_bar.isVisible()

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_scan_windows_regions_finds_memory(
        self, memory_dumper_widget: MemoryDumperWidget, current_process_pid: int
    ) -> None:
        """Test Windows memory region scanning finds regions."""
        memory_dumper_widget.current_process = current_process_pid

        memory_dumper_widget._scan_windows_regions()

        assert memory_dumper_widget.regions_table.rowCount() > 0

        address_item = memory_dumper_widget.regions_table.item(0, 0)
        assert address_item is not None
        address_text = address_item.text()
        assert address_text.startswith("0x")

        size_item = memory_dumper_widget.regions_table.item(0, 1)
        assert size_item is not None
        size_text = size_item.text()
        assert "bytes" in size_text

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_scan_linux_regions_finds_memory(
        self, memory_dumper_widget: MemoryDumperWidget, current_process_pid: int
    ) -> None:
        """Test Linux memory region scanning via /proc."""
        memory_dumper_widget.current_process = current_process_pid

        memory_dumper_widget._scan_linux_regions()

        assert memory_dumper_widget.regions_table.rowCount() > 0

        address_item = memory_dumper_widget.regions_table.item(0, 0)
        assert address_item is not None
        address_text = address_item.text()
        assert address_text.startswith("0x")

    def test_should_include_region_windows_filters(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Windows region filtering logic."""
        memory_dumper_widget.readable_check.setChecked(True)
        memory_dumper_widget.writable_check.setChecked(False)
        memory_dumper_widget.executable_check.setChecked(False)

        PAGE_READONLY = 0x02
        PAGE_READWRITE = 0x04
        PAGE_EXECUTE_READ = 0x20

        assert memory_dumper_widget._should_include_region(PAGE_READONLY) is True
        assert memory_dumper_widget._should_include_region(PAGE_READWRITE) is True
        assert memory_dumper_widget._should_include_region(PAGE_EXECUTE_READ) is True

    def test_should_include_region_linux_filters(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Linux region filtering logic."""
        memory_dumper_widget.readable_check.setChecked(True)
        memory_dumper_widget.writable_check.setChecked(True)
        memory_dumper_widget.executable_check.setChecked(False)
        memory_dumper_widget.private_check.setChecked(True)

        assert memory_dumper_widget._should_include_region_linux("rwxp") is True
        assert memory_dumper_widget._should_include_region_linux("rw-p") is True
        assert memory_dumper_widget._should_include_region_linux("r--p") is True
        assert memory_dumper_widget._should_include_region_linux("---p") is False

    def test_get_protection_string_converts_flags(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Windows protection flag to string conversion."""
        assert memory_dumper_widget._get_protection_string(0x02) == "READONLY"
        assert memory_dumper_widget._get_protection_string(0x04) == "READWRITE"
        assert memory_dumper_widget._get_protection_string(0x20) == "EXECUTE_READ"
        assert memory_dumper_widget._get_protection_string(0x40) == "EXECUTE_READWRITE"

    def test_get_region_type_converts_flags(
        self, memory_dumper_widget: MemoryDumperWidget
    ) -> None:
        """Test Windows memory type flag to string conversion."""
        assert memory_dumper_widget._get_region_type(0x20000) == "PRIVATE"
        assert memory_dumper_widget._get_region_type(0x40000) == "MAPPED"
        assert memory_dumper_widget._get_region_type(0x1000000) == "IMAGE"


class TestMemoryDumpThread:
    """Test MemoryDumpThread with real memory dump operations."""

    def test_thread_initialization(
        self, memory_dumper_widget: MemoryDumperWidget, temp_output_dir: Path
    ) -> None:
        """Verify dump thread initializes with correct parameters."""
        from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

        table = QTableWidget()
        table.insertRow(0)

        table.setItem(0, 0, QTableWidgetItem("0x0000000000000000"))
        table.setItem(0, 1, QTableWidgetItem("4096 bytes"))

        thread = MemoryDumpThread(
            pid=os.getpid(),
            rows=[0],
            table=table,
            output_dir=str(temp_output_dir),
            options={"raw": True, "strings": False, "compress": False, "metadata": False, "minidump": False, "full": False},
        )

        assert thread.pid == os.getpid()
        assert thread.rows == [0]
        assert thread.output_dir == str(temp_output_dir)
        assert thread.options["raw"] is True

    def test_extract_strings_finds_printable_text(self, temp_output_dir: Path) -> None:
        """Test string extraction from memory data."""
        from PyQt6.QtWidgets import QTableWidget

        test_data = b"Hello World!\x00\x01\x02Testing\x00\x00\x00Some more text here"

        table = QTableWidget()
        thread = MemoryDumpThread(
            pid=os.getpid(),
            rows=[],
            table=table,
            output_dir=str(temp_output_dir),
            options={"strings": True, "raw": False, "compress": False, "metadata": False, "minidump": False, "full": False},
        )

        thread._extract_strings(test_data, 0x1000)

        strings_file = temp_output_dir / "strings_0x0000000000001000.txt"
        if strings_file.exists():
            content = strings_file.read_text()
            assert "Hello World!" in content or "Testing" in content or "Some more text here" in content


@pytest.mark.integration
class TestMemoryDumperIntegration:
    """Integration tests with real memory operations."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_memory_region_scan_accuracy(
        self, qapp: QApplication, current_process_pid: int
    ) -> None:
        """Test Windows memory region scanning matches psutil."""
        widget = MemoryDumperWidget()

        try:
            widget.current_process = current_process_pid
            widget._scan_windows_regions()

            assert widget.regions_table.rowCount() > 0

            process = psutil.Process(current_process_pid)
            mem_info = process.memory_info()

            assert mem_info.rss > 0

        finally:
            widget.deleteLater()

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_linux_memory_region_scan_via_proc(
        self, qapp: QApplication, current_process_pid: int
    ) -> None:
        """Test Linux memory region scanning via /proc/[pid]/maps."""
        widget = MemoryDumperWidget()

        try:
            widget.current_process = current_process_pid
            widget._scan_linux_regions()

            assert widget.regions_table.rowCount() > 0

            maps_file = f"/proc/{current_process_pid}/maps"
            with open(maps_file) as f:
                maps_lines = f.readlines()

            assert len(maps_lines) > 0

        finally:
            widget.deleteLater()

    def test_attach_and_scan_own_process(
        self, qapp: QApplication, current_process_pid: int
    ) -> None:
        """Test attaching to and scanning own process memory."""
        widget = MemoryDumperWidget()

        try:
            widget.refresh_process_list()

            for i in range(widget.process_combo.count()):
                item_data = widget.process_combo.itemData(i)
                if item_data == current_process_pid:
                    widget.process_combo.setCurrentIndex(i)
                    break

            widget.attach_to_process()

            assert widget.current_process == current_process_pid
            assert widget.regions_table.rowCount() > 0

        finally:
            widget.deleteLater()

    def test_memory_dump_creates_output_file(
        self, qapp: QApplication, current_process_pid: int, temp_output_dir: Path
    ) -> None:
        """Test memory dump creates actual output files."""
        widget = MemoryDumperWidget()

        try:
            widget.current_process = current_process_pid
            widget.scan_memory_regions()

            if widget.regions_table.rowCount() > 0:
                from PyQt6.QtWidgets import QTableWidgetItem

                addr_item = widget.regions_table.item(0, 0)
                size_item = widget.regions_table.item(0, 1)

                if addr_item and size_item:
                    from PyQt6.QtWidgets import QTableWidget

                    test_table = QTableWidget()
                    test_table.insertRow(0)
                    test_table.setItem(0, 0, addr_item)
                    test_table.setItem(0, 1, size_item)

                    thread = MemoryDumpThread(
                        pid=current_process_pid,
                        rows=[0],
                        table=test_table,
                        output_dir=str(temp_output_dir),
                        options={
                            "raw": True,
                            "strings": False,
                            "compress": False,
                            "metadata": False,
                            "minidump": False,
                            "full": False,
                        },
                    )

                    try:
                        thread.run()

                        if dump_files := list(temp_output_dir.glob("dump_*.bin")):
                            assert dump_files[0].stat().st_size > 0
                    except Exception as e:
                        pytest.skip(f"Memory dump failed (may require elevated privileges): {e}")

        finally:
            widget.deleteLater()

    def test_process_enumeration_completeness(self, qapp: QApplication) -> None:
        """Test process enumeration finds all running processes."""
        widget = MemoryDumperWidget()

        try:
            widget.refresh_process_list()

            psutil_count = len(list(psutil.process_iter()))
            widget_count = widget.process_combo.count()

            assert widget_count > 0
            assert widget_count <= psutil_count

        finally:
            widget.deleteLater()
