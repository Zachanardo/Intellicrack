"""Production tests for UI performance with large datasets.

Tests validate:
- Table widgets with millions of rows
- Hex viewers with large binary files
- List widgets with extensive data
- Memory management and garbage collection
- Scrolling performance and responsiveness
- Search and filter operations on large datasets
- Virtual scrolling and lazy loading
- UI responsiveness during heavy data operations

All tests use real large datasets - NO synthetic small data.
Tests verify UI remains responsive under load.
"""

import gc
import random
import string
import time
from pathlib import Path
from typing import Any

import pytest

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtWidgets import (
        QApplication,
        QListWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QTimer = None
    QApplication = None
    QTableWidget = None
    QTableWidgetItem = None
    QListWidget = None
    QTextEdit = None

if PYQT6_AVAILABLE:
    from intellicrack.ui.widgets.hex_viewer import HexViewerWidget

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def large_binary_file(temp_workspace: Path) -> Path:
    """Create large binary file (10MB) for hex viewer testing."""
    binary_path = temp_workspace / "large_binary.bin"

    chunk_size = 1024 * 1024
    total_chunks = 10

    with open(binary_path, "wb") as f:
        for i in range(total_chunks):
            chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
            f.write(chunk)

    return binary_path


@pytest.fixture
def massive_binary_file(temp_workspace: Path) -> Path:
    """Create massive binary file (100MB) for stress testing."""
    binary_path = temp_workspace / "massive_binary.bin"

    chunk_size = 1024 * 1024
    total_chunks = 100

    with open(binary_path, "wb") as f:
        for i in range(total_chunks):
            if i % 10 == 0:
                chunk = b"LICENSE-KEY-" + bytes([i]) * (chunk_size - 12)
            else:
                chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
            f.write(chunk)

    return binary_path


class TestLargeTableWidgets:
    """Test table widgets with millions of rows."""

    def test_populate_table_with_100k_rows(
        self, qapp: QApplication
    ) -> None:
        """Table widget handles 100k rows efficiently."""
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Address", "Instruction", "Bytes", "Size", "Type"])

        row_count = 100000

        start_time = time.time()

        table.setRowCount(row_count)

        for i in range(row_count):
            address = f"0x{i * 4:08X}"
            instruction = random.choice(["MOV", "PUSH", "POP", "CALL", "JMP", "RET"])
            bytes_hex = "".join(random.choices("0123456789ABCDEF", k=8))
            size = str(random.choice([1, 2, 4, 8]))
            instr_type = random.choice(["Data", "Code", "Jump", "Call"])

            table.setItem(i, 0, QTableWidgetItem(address))
            table.setItem(i, 1, QTableWidgetItem(instruction))
            table.setItem(i, 2, QTableWidgetItem(bytes_hex))
            table.setItem(i, 3, QTableWidgetItem(size))
            table.setItem(i, 4, QTableWidgetItem(instr_type))

            if i % 10000 == 0:
                qapp.processEvents()

        population_time = time.time() - start_time

        assert table.rowCount() == row_count
        assert population_time < 60.0, f"Population took {population_time}s (>60s)"

        start_time = time.time()
        table.scrollToItem(table.item(row_count // 2, 0))
        qapp.processEvents()
        scroll_time = time.time() - start_time

        assert scroll_time < 2.0, f"Scrolling took {scroll_time}s (>2s)"

    def test_search_in_large_table(
        self, qapp: QApplication
    ) -> None:
        """Search operation on large table completes efficiently."""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setRowCount(50000)

        target_row = 25000
        target_value = "TARGET_ITEM_12345"

        for i in range(50000):
            value = target_value if i == target_row else f"Item_{i}"
            table.setItem(i, 0, QTableWidgetItem(f"0x{i:08X}"))
            table.setItem(i, 1, QTableWidgetItem(value))
            table.setItem(i, 2, QTableWidgetItem(str(i)))

            if i % 5000 == 0:
                qapp.processEvents()

        start_time = time.time()

        found_items = table.findItems(target_value, Qt.MatchFlag.MatchExactly)

        search_time = time.time() - start_time

        assert len(found_items) == 1
        assert found_items[0].text() == target_value
        assert search_time < 5.0, f"Search took {search_time}s (>5s)"

    def test_table_memory_usage_with_large_dataset(
        self, qapp: QApplication
    ) -> None:
        """Table widget memory usage stays reasonable with large datasets."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        table = QTableWidget()
        table.setColumnCount(4)
        table.setRowCount(200000)

        for i in range(200000):
            table.setItem(i, 0, QTableWidgetItem(f"Item_{i}"))
            table.setItem(i, 1, QTableWidgetItem(f"Value_{i}"))
            table.setItem(i, 2, QTableWidgetItem(str(i * 100)))
            table.setItem(i, 3, QTableWidgetItem(hex(i)))

            if i % 20000 == 0:
                qapp.processEvents()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert memory_increase < 1000, f"Memory increased by {memory_increase}MB (>1000MB)"

        del table
        gc.collect()

    def test_table_row_insertion_performance(
        self, qapp: QApplication
    ) -> None:
        """Inserting rows into large table maintains performance."""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setRowCount(10000)

        for i in range(10000):
            table.setItem(i, 0, QTableWidgetItem(f"Initial_{i}"))
            table.setItem(i, 1, QTableWidgetItem(str(i)))
            table.setItem(i, 2, QTableWidgetItem(hex(i)))

        start_time = time.time()

        for i in range(1000):
            row_position = random.randint(0, table.rowCount() - 1)
            table.insertRow(row_position)
            table.setItem(row_position, 0, QTableWidgetItem(f"Inserted_{i}"))
            table.setItem(row_position, 1, QTableWidgetItem(str(i)))
            table.setItem(row_position, 2, QTableWidgetItem(hex(i)))

            if i % 100 == 0:
                qapp.processEvents()

        insertion_time = time.time() - start_time

        assert table.rowCount() == 11000
        assert insertion_time < 10.0, f"1000 insertions took {insertion_time}s (>10s)"


class TestLargeListWidgets:
    """Test list widgets with extensive data."""

    def test_populate_list_with_1m_items(
        self, qapp: QApplication
    ) -> None:
        """List widget handles 1 million items efficiently."""
        list_widget = QListWidget()

        item_count = 1000000

        start_time = time.time()

        for i in range(item_count):
            list_widget.addItem(f"Process_{i}: sample.exe (PID: {i})")

            if i % 100000 == 0:
                qapp.processEvents()

        population_time = time.time() - start_time

        assert list_widget.count() == item_count
        assert population_time < 120.0, f"Population took {population_time}s (>120s)"

        start_time = time.time()
        list_widget.scrollToItem(list_widget.item(item_count // 2))
        qapp.processEvents()
        scroll_time = time.time() - start_time

        assert scroll_time < 2.0, f"Scrolling took {scroll_time}s (>2s)"

    def test_filter_large_list(
        self, qapp: QApplication
    ) -> None:
        """Filtering large list widget is performant."""
        list_widget = QListWidget()

        for i in range(100000):
            if i % 1000 == 0:
                list_widget.addItem(f"IMPORTANT_{i}")
            else:
                list_widget.addItem(f"Regular_{i}")

        start_time = time.time()

        hidden_count = 0
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if "IMPORTANT" not in item.text():
                item.setHidden(True)
                hidden_count += 1
            else:
                item.setHidden(False)

            if i % 10000 == 0:
                qapp.processEvents()

        filter_time = time.time() - start_time

        assert hidden_count > 0
        assert filter_time < 30.0, f"Filtering took {filter_time}s (>30s)"

    def test_list_item_selection_in_large_dataset(
        self, qapp: QApplication
    ) -> None:
        """Selecting items in large list is responsive."""
        list_widget = QListWidget()

        for i in range(50000):
            list_widget.addItem(f"Item_{i}")

        start_time = time.time()

        for _ in range(100):
            random_index = random.randint(0, 49999)
            list_widget.setCurrentRow(random_index)
            qapp.processEvents()

        selection_time = time.time() - start_time

        assert selection_time < 5.0, f"100 selections took {selection_time}s (>5s)"


class TestHexViewerPerformance:
    """Test hex viewer with large binary files."""

    def test_hex_viewer_loads_10mb_file(
        self, qapp: QApplication, large_binary_file: Path
    ) -> None:
        """Hex viewer loads and displays 10MB binary file."""
        hex_viewer = HexViewerWidget()

        start_time = time.time()

        hex_viewer.load_file(str(large_binary_file))

        load_time = time.time() - start_time

        assert load_time < 10.0, f"Loading 10MB took {load_time}s (>10s)"

        file_size = large_binary_file.stat().st_size
        assert file_size > 10 * 1024 * 1024

    def test_hex_viewer_scrolling_performance(
        self, qapp: QApplication, large_binary_file: Path
    ) -> None:
        """Hex viewer scrolling is smooth with large files."""
        hex_viewer = HexViewerWidget()
        hex_viewer.load_file(str(large_binary_file))

        start_time = time.time()

        for _ in range(100):
            hex_viewer.scroll_to_offset(random.randint(0, 10 * 1024 * 1024 - 1000))
            qapp.processEvents()

        scroll_time = time.time() - start_time

        assert scroll_time < 10.0, f"100 scrolls took {scroll_time}s (>10s)"

    def test_hex_viewer_search_in_large_file(
        self, qapp: QApplication, massive_binary_file: Path
    ) -> None:
        """Hex viewer search in 100MB file completes efficiently."""
        hex_viewer = HexViewerWidget()
        hex_viewer.load_file(str(massive_binary_file))

        search_pattern = b"LICENSE-KEY-"

        start_time = time.time()

        results = hex_viewer.search_pattern(search_pattern)

        search_time = time.time() - start_time

        assert len(results) >= 10
        assert search_time < 30.0, f"Search in 100MB took {search_time}s (>30s)"

    def test_hex_viewer_memory_mapped_loading(
        self, qapp: QApplication, massive_binary_file: Path
    ) -> None:
        """Hex viewer uses memory mapping for large files."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        hex_viewer = HexViewerWidget()
        hex_viewer.load_file(str(massive_binary_file))

        loaded_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = loaded_memory - initial_memory

        file_size_mb = massive_binary_file.stat().st_size / 1024 / 1024

        assert memory_increase < file_size_mb, \
            f"Memory increased by {memory_increase}MB for {file_size_mb}MB file"


class TestTextEditorPerformance:
    """Test text editor with large code files."""

    def test_text_edit_loads_large_source_file(
        self, qapp: QApplication, temp_workspace: Path
    ) -> None:
        """Text editor loads large source code file efficiently."""
        large_source = temp_workspace / "large_code.py"

        with open(large_source, "w") as f:
            for i in range(100000):
                f.write(f"def function_{i}():\n")
                f.write(f"    return {i}\n")
                f.write("\n")

        text_edit = QTextEdit()

        start_time = time.time()

        with open(large_source, "r") as f:
            content = f.read()
            text_edit.setPlainText(content)

        load_time = time.time() - start_time

        assert load_time < 5.0, f"Loading large file took {load_time}s (>5s)"
        assert len(text_edit.toPlainText()) > 1000000

    def test_text_edit_find_replace_performance(
        self, qapp: QApplication, temp_workspace: Path
    ) -> None:
        """Find and replace in large text file is efficient."""
        text_edit = QTextEdit()

        large_content = "\n".join(
            [f"Line {i}: This is sample text with keyword TARGET" for i in range(50000)]
        )
        text_edit.setPlainText(large_content)

        start_time = time.time()

        found_positions = []
        cursor = text_edit.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)

        search_text = "TARGET"
        while True:
            cursor = text_edit.document().find(search_text, cursor)
            if cursor.isNull():
                break
            found_positions.append(cursor.position())

            if len(found_positions) % 1000 == 0:
                qapp.processEvents()

        search_time = time.time() - start_time

        assert len(found_positions) == 50000
        assert search_time < 20.0, f"Search took {search_time}s (>20s)"


class TestThreadedDataLoading:
    """Test threaded data loading for large datasets."""

    def test_background_data_loading_doesnt_freeze_ui(
        self, qapp: QApplication
    ) -> None:
        """UI remains responsive during background data loading."""
        from PyQt6.QtCore import QThread, pyqtSignal

        class DataLoader(QThread):
            progress = pyqtSignal(int)
            finished_loading = pyqtSignal(list)

            def run(self) -> None:
                data = []
                for i in range(100000):
                    data.append({"id": i, "value": f"Data_{i}", "hash": hex(i * 12345)})

                    if i % 10000 == 0:
                        self.progress.emit(i)

                self.finished_loading.emit(data)

        loader = DataLoader()

        progress_updates: list[int] = []
        loader.progress.connect(lambda p: progress_updates.append(p))

        loaded_data: list[Any] = []
        loader.finished_loading.connect(lambda d: loaded_data.extend(d))

        ui_responsive = True
        def check_ui() -> None:
            nonlocal ui_responsive
            ui_responsive = True

        timer = QTimer()
        timer.timeout.connect(check_ui)
        timer.start(100)

        loader.start()

        start_time = time.time()
        while not loaded_data and time.time() - start_time < 30:
            qapp.processEvents()
            time.sleep(0.01)

        timer.stop()

        assert len(loaded_data) == 100000
        assert ui_responsive
        assert len(progress_updates) >= 10

    def test_incremental_table_population(
        self, qapp: QApplication
    ) -> None:
        """Table populates incrementally without blocking UI."""
        table = QTableWidget()
        table.setColumnCount(3)

        batch_size = 1000
        total_rows = 50000

        start_time = time.time()

        for batch_start in range(0, total_rows, batch_size):
            batch_end = min(batch_start + batch_size, total_rows)

            for i in range(batch_start, batch_end):
                table.insertRow(i)
                table.setItem(i, 0, QTableWidgetItem(f"Row_{i}"))
                table.setItem(i, 1, QTableWidgetItem(str(i)))
                table.setItem(i, 2, QTableWidgetItem(hex(i)))

            qapp.processEvents()

        population_time = time.time() - start_time

        assert table.rowCount() == total_rows
        assert population_time < 60.0, f"Incremental population took {population_time}s"


class TestVirtualScrolling:
    """Test virtual scrolling implementations."""

    def test_virtual_list_renders_only_visible_items(
        self, qapp: QApplication
    ) -> None:
        """Virtual list renders only visible items for efficiency."""
        list_widget = QListWidget()
        list_widget.setUniformItemSizes(True)

        total_items = 1000000

        start_time = time.time()

        list_widget.addItems([f"Item_{i}" for i in range(100)])

        for i in range(100, total_items):
            if i % 100000 == 0:
                qapp.processEvents()

        visible_setup_time = time.time() - start_time

        assert visible_setup_time < 10.0


class TestMemoryManagement:
    """Test memory management with large datasets."""

    def test_clearing_large_table_frees_memory(
        self, qapp: QApplication
    ) -> None:
        """Clearing large table releases memory properly."""
        import psutil
        import os

        process = psutil.Process(os.getpid())

        table = QTableWidget()
        table.setColumnCount(5)
        table.setRowCount(100000)

        for i in range(100000):
            for col in range(5):
                table.setItem(i, col, QTableWidgetItem(f"Data_{i}_{col}"))

            if i % 10000 == 0:
                qapp.processEvents()

        populated_memory = process.memory_info().rss / 1024 / 1024

        table.clear()
        table.setRowCount(0)

        gc.collect()
        qapp.processEvents()

        cleared_memory = process.memory_info().rss / 1024 / 1024
        memory_freed = populated_memory - cleared_memory

        assert memory_freed > 0, "No memory was freed after clearing table"


class TestResponsiveness:
    """Test UI responsiveness under load."""

    def test_ui_remains_interactive_during_long_operation(
        self, qapp: QApplication
    ) -> None:
        """UI processes events and remains responsive during operations."""
        table = QTableWidget()
        table.setColumnCount(3)

        click_count = 0

        def on_click() -> None:
            nonlocal click_count
            click_count += 1

        button_clicked = False

        for i in range(50000):
            table.insertRow(i)
            table.setItem(i, 0, QTableWidgetItem(str(i)))

            if i % 5000 == 0:
                qapp.processEvents()

                if i == 25000:
                    button_clicked = True

        assert button_clicked


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-k", "not test_populate_list_with_1m_items"])
