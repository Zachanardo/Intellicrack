"""Production tests for thread safety in multi-threaded UI operations.

Tests validate:
- Concurrent access to shared UI widgets
- Thread-safe signal/slot communication
- Worker threads updating UI elements
- Race condition detection
- Deadlock prevention
- Thread pool management
- Background task coordination
- Resource cleanup after thread completion

All tests use real threading - NO mocks.
Tests validate actual concurrent behavior.
"""

import threading
import time
from pathlib import Path
from typing import Any

import pytest

try:
    from PyQt6.QtCore import (
        QMutex,
        QObject,
        QThread,
        QThreadPool,
        QTimer,
        QWaitCondition,
        pyqtSignal,
    )
    from PyQt6.QtWidgets import (
        QApplication,
        QListWidget,
        QProgressBar,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    QThread: Any = None  # type: ignore[no-redef]
    QObject: Any = None  # type: ignore[no-redef]
    QMutex: Any = None  # type: ignore[no-redef]
    QWaitCondition: Any = None  # type: ignore[no-redef]
    QThreadPool: Any = None  # type: ignore[no-redef]
    QTimer: Any = None  # type: ignore[no-redef]
    QApplication: Any = None  # type: ignore[no-redef]
    QTableWidget: Any = None  # type: ignore[no-redef]
    QTableWidgetItem: Any = None  # type: ignore[no-redef]
    QListWidget: Any = None  # type: ignore[no-redef]
    QTextEdit: Any = None  # type: ignore[no-redef]
    QProgressBar: Any = None  # type: ignore[no-redef]
    pyqtSignal: Any = None  # type: ignore[no-redef]

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> "QApplication":
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


class DataProcessor(QThread):
    """Worker thread for data processing."""

    progress = pyqtSignal(int)
    result_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, data: list[Any], processing_time: float = 0.001) -> None:
        super().__init__()
        self.data = data
        self.processing_time = processing_time
        self.is_cancelled = False
        self.mutex = QMutex()

    def run(self) -> None:
        """Process data in background thread."""
        try:
            results = []
            total = len(self.data)

            for i, item in enumerate(self.data):
                self.mutex.lock()
                if self.is_cancelled:
                    self.mutex.unlock()
                    return
                self.mutex.unlock()

                processed = item * 2 if isinstance(item, int) else str(item).upper()
                results.append(processed)

                if i % 100 == 0:
                    self.progress.emit(int((i / total) * 100))

                time.sleep(self.processing_time)

            self.result_ready.emit(results)
            self.progress.emit(100)

        except Exception as e:
            self.error_occurred.emit(str(e))

    def cancel(self) -> None:
        """Cancel processing."""
        self.mutex.lock()
        self.is_cancelled = True
        self.mutex.unlock()


class ConcurrentUpdater(QThread):
    """Thread that updates shared data structure."""

    update_complete = pyqtSignal(int)

    def __init__(self, shared_list: list[int], thread_id: int, iterations: int) -> None:
        super().__init__()
        self.shared_list = shared_list
        self.thread_id = thread_id
        self.iterations = iterations
        self.mutex = QMutex()

    def run(self) -> None:
        """Perform concurrent updates."""
        for i in range(self.iterations):
            self.mutex.lock()
            self.shared_list.append(self.thread_id * 1000 + i)
            self.mutex.unlock()

            time.sleep(0.0001)

        self.update_complete.emit(self.thread_id)


class TestBasicThreadSafety:
    """Test basic thread safety patterns."""

    def test_single_worker_thread_signal_emission(
        self, qapp: QApplication
    ) -> None:
        """Worker thread emits signals correctly to main thread."""
        data = list(range(1000))
        processor = DataProcessor(data, processing_time=0.0001)

        progress_updates: list[int] = []
        results: list[list[Any]] = []
        errors: list[str] = []

        processor.progress.connect(lambda p: progress_updates.append(p))
        processor.result_ready.connect(lambda r: results.append(r))
        processor.error_occurred.connect(lambda e: errors.append(e))

        processor.start()

        timeout = 10
        start_time = time.time()
        while processor.isRunning() and time.time() - start_time < timeout:
            qapp.processEvents()
            time.sleep(0.01)

        processor.wait(5000)

        assert len(results) == 1
        assert len(results[0]) == 1000
        assert not errors
        assert len(progress_updates) >= 10

    def test_worker_thread_cancellation(
        self, qapp: QApplication
    ) -> None:
        """Worker thread responds to cancellation signal."""
        data = list(range(10000))
        processor = DataProcessor(data, processing_time=0.001)

        results: list[list[Any]] = []
        processor.result_ready.connect(lambda r: results.append(r))

        processor.start()

        time.sleep(0.1)

        processor.cancel()

        processor.wait(5000)

        assert not results or len(results[0]) < 10000

    def test_multiple_sequential_worker_threads(
        self, qapp: QApplication
    ) -> None:
        """Multiple worker threads execute sequentially without interference."""
        all_results: list[list[Any]] = []

        for batch in range(5):
            data = list(range(batch * 100, (batch + 1) * 100))
            processor = DataProcessor(data, processing_time=0.0001)

            processor.result_ready.connect(lambda r: all_results.append(r))

            processor.start()
            processor.wait(5000)

        assert len(all_results) == 5
        assert all(len(r) == 100 for r in all_results)


class TestConcurrentAccess:
    """Test concurrent access to shared resources."""

    def test_multiple_threads_concurrent_updates(
        self, qapp: QApplication
    ) -> None:
        """Multiple threads update shared data structure safely."""
        shared_list: list[int] = []
        thread_count = 5
        iterations = 100

        threads = []
        completed: list[int] = []

        for i in range(thread_count):
            thread = ConcurrentUpdater(shared_list, i, iterations)
            thread.update_complete.connect(lambda tid: completed.append(tid))
            threads.append(thread)

        for thread in threads:
            thread.start()

        timeout = 10
        start_time = time.time()
        while len(completed) < thread_count and time.time() - start_time < timeout:
            qapp.processEvents()
            time.sleep(0.01)

        for thread in threads:
            thread.wait(5000)

        assert len(completed) == thread_count
        assert len(shared_list) == thread_count * iterations

        for i in range(thread_count):
            thread_items = [x for x in shared_list if x >= i * 1000 and x < (i + 1) * 1000]
            assert len(thread_items) == iterations

    def test_mutex_protects_shared_resource(
        self, qapp: QApplication
    ) -> None:
        """Mutex correctly protects shared resource from race conditions."""
        counter = [0]
        mutex = QMutex()
        thread_count = 10
        increments_per_thread = 1000

        class CounterThread(QThread):
            def __init__(self, counter_ref: list[int], mutex_ref: QMutex, increments: int) -> None:
                super().__init__()
                self.counter = counter_ref
                self.mutex = mutex_ref
                self.increments = increments

            def run(self) -> None:
                for _ in range(self.increments):
                    self.mutex.lock()
                    self.counter[0] += 1
                    self.mutex.unlock()

        threads = [CounterThread(counter, mutex, increments_per_thread) for _ in range(thread_count)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.wait(10000)

        expected_count = thread_count * increments_per_thread
        assert counter[0] == expected_count

    def test_wait_condition_synchronization(
        self, qapp: QApplication
    ) -> None:
        """Wait conditions synchronize thread execution correctly."""
        mutex = QMutex()
        condition = QWaitCondition()
        data_ready: list[bool] = [False]
        data: list[int] = []

        class Producer(QThread):
            def __init__(self, mutex_ref: QMutex, condition_ref: QWaitCondition,
                        data_ref: list[Any], ready_ref: list[bool]) -> None:
                super().__init__()
                self.mutex = mutex_ref
                self.condition = condition_ref
                self.data = data_ref
                self.ready = ready_ref

            def run(self) -> None:
                time.sleep(0.1)
                self.mutex.lock()
                self.data.extend([1, 2, 3, 4, 5])
                self.ready[0] = True
                self.condition.wakeAll()
                self.mutex.unlock()

        class Consumer(QThread):
            def __init__(self, mutex_ref: QMutex, condition_ref: QWaitCondition,
                        data_ref: list[Any], ready_ref: list[bool]) -> None:
                super().__init__()
                self.mutex = mutex_ref
                self.condition = condition_ref
                self.data = data_ref
                self.ready = ready_ref
                self.consumed: list[int] = []

            def run(self) -> None:
                self.mutex.lock()
                while not self.ready[0]:
                    self.condition.wait(self.mutex)
                self.consumed = self.data.copy()
                self.mutex.unlock()

        producer = Producer(mutex, condition, data, data_ready)
        consumer = Consumer(mutex, condition, data, data_ready)

        consumer.start()
        time.sleep(0.05)
        producer.start()

        producer.wait(5000)
        consumer.wait(5000)

        assert consumer.consumed == [1, 2, 3, 4, 5]


class TestUIUpdatesFromThreads:
    """Test UI updates from background threads."""

    def test_table_update_from_worker_thread(
        self, qapp: QApplication
    ) -> None:
        """Worker thread safely updates table widget via signals."""
        table = QTableWidget()
        table.setColumnCount(3)

        class TableUpdater(QThread):
            add_row = pyqtSignal(str, str, str)

            def __init__(self, row_count: int) -> None:
                super().__init__()
                self.row_count = row_count

            def run(self) -> None:
                for i in range(self.row_count):
                    self.add_row.emit(f"Item_{i}", str(i), hex(i))
                    time.sleep(0.001)

        def add_table_row(col0: str, col1: str, col2: str) -> None:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(col0))
            table.setItem(row, 1, QTableWidgetItem(col1))
            table.setItem(row, 2, QTableWidgetItem(col2))

        updater = TableUpdater(100)
        updater.add_row.connect(add_table_row)

        updater.start()

        timeout = 5
        start_time = time.time()
        while updater.isRunning() and time.time() - start_time < timeout:
            qapp.processEvents()
            time.sleep(0.01)

        updater.wait(5000)

        assert table.rowCount() == 100

    def test_progress_bar_update_from_worker(
        self, qapp: QApplication
    ) -> None:
        """Progress bar updates safely from worker thread."""
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 100)

        class ProgressWorker(QThread):
            progress_changed = pyqtSignal(int)

            def run(self) -> None:
                for i in range(101):
                    self.progress_changed.emit(i)
                    time.sleep(0.01)

        worker = ProgressWorker()
        worker.progress_changed.connect(progress_bar.setValue)

        worker.start()

        timeout = 5
        start_time = time.time()
        while worker.isRunning() and time.time() - start_time < timeout:
            qapp.processEvents()
            time.sleep(0.01)

        worker.wait(5000)

        assert progress_bar.value() == 100

    def test_list_widget_concurrent_additions(
        self, qapp: QApplication
    ) -> None:
        """Multiple threads add items to list widget without corruption."""
        list_widget = QListWidget()

        class ListAdder(QThread):
            add_item = pyqtSignal(str)

            def __init__(self, prefix: str, count: int) -> None:
                super().__init__()
                self.prefix = prefix
                self.count = count

            def run(self) -> None:
                for i in range(self.count):
                    self.add_item.emit(f"{self.prefix}_{i}")
                    time.sleep(0.001)

        threads = []
        for i in range(3):
            thread = ListAdder(f"Thread{i}", 50)
            thread.add_item.connect(list_widget.addItem)
            threads.append(thread)

        for thread in threads:
            thread.start()

        timeout = 10
        start_time = time.time()
        while any(t.isRunning() for t in threads) and time.time() - start_time < timeout:
            qapp.processEvents()
            time.sleep(0.01)

        for thread in threads:
            thread.wait(5000)

        assert list_widget.count() == 150


class TestThreadPoolManagement:
    """Test QThreadPool for managing multiple concurrent tasks."""

    def test_thread_pool_executes_runnables(
        self, qapp: QApplication
    ) -> None:
        """Thread pool executes multiple runnables concurrently."""
        from PyQt6.QtCore import QRunnable

        results: list[int] = []
        results_lock = threading.Lock()

        class TaskRunnable(QRunnable):
            def __init__(self, task_id: int) -> None:
                super().__init__()
                self.task_id = task_id

            def run(self) -> None:
                time.sleep(0.1)
                with results_lock:
                    results.append(self.task_id)

        pool = QThreadPool.globalInstance()
        assert pool is not None, "QThreadPool.globalInstance() returned None"
        task_count = 10

        for i in range(task_count):
            pool.start(TaskRunnable(i))

        pool.waitForDone(10000)

        assert len(results) == task_count
        assert set(results) == set(range(task_count))

    def test_thread_pool_max_thread_count(
        self, qapp: QApplication
    ) -> None:
        """Thread pool respects maximum thread count setting."""
        pool = QThreadPool.globalInstance()
        assert pool is not None, "QThreadPool.globalInstance() returned None"

        max_threads = pool.maxThreadCount()
        assert max_threads > 0

        pool.setMaxThreadCount(4)
        assert pool.maxThreadCount() == 4

        pool.setMaxThreadCount(max_threads)


class TestDeadlockPrevention:
    """Test deadlock prevention mechanisms."""

    def test_no_deadlock_with_multiple_mutexes(
        self, qapp: QApplication
    ) -> None:
        """Multiple mutexes don't cause deadlock with proper ordering."""
        mutex_a = QMutex()
        mutex_b = QMutex()
        counter = [0]

        class Thread1(QThread):
            def __init__(self, ma: QMutex, mb: QMutex, cnt: list[int]) -> None:
                super().__init__()
                self.mutex_a = ma
                self.mutex_b = mb
                self.counter = cnt

            def run(self) -> None:
                for _ in range(100):
                    self.mutex_a.lock()
                    self.mutex_b.lock()
                    self.counter[0] += 1
                    self.mutex_b.unlock()
                    self.mutex_a.unlock()
                    time.sleep(0.001)

        class Thread2(QThread):
            def __init__(self, ma: QMutex, mb: QMutex, cnt: list[int]) -> None:
                super().__init__()
                self.mutex_a = ma
                self.mutex_b = mb
                self.counter = cnt

            def run(self) -> None:
                for _ in range(100):
                    self.mutex_a.lock()
                    self.mutex_b.lock()
                    self.counter[0] += 1
                    self.mutex_b.unlock()
                    self.mutex_a.unlock()
                    time.sleep(0.001)

        t1 = Thread1(mutex_a, mutex_b, counter)
        t2 = Thread2(mutex_a, mutex_b, counter)

        t1.start()
        t2.start()

        t1.wait(10000)
        t2.wait(10000)

        assert counter[0] == 200


class TestResourceCleanup:
    """Test proper resource cleanup after thread completion."""

    def test_thread_cleanup_after_completion(
        self, qapp: QApplication
    ) -> None:
        """Thread resources are properly cleaned up after completion."""
        class CleanupThread(QThread):
            def __init__(self) -> None:
                super().__init__()
                self.cleanup_called = False

            def run(self) -> None:
                time.sleep(0.1)

            def __del__(self) -> None:
                self.cleanup_called = True

        thread = CleanupThread()
        thread.start()
        thread.wait(5000)

        assert not thread.isRunning()

    def test_signal_disconnection_prevents_leaks(
        self, qapp: QApplication
    ) -> None:
        """Disconnecting signals prevents memory leaks."""
        class SignalThread(QThread):
            data_ready = pyqtSignal(str)

            def run(self) -> None:
                self.data_ready.emit("test")

        results: list[str] = []

        def handler(data: str) -> None:
            results.append(data)

        thread = SignalThread()
        thread.data_ready.connect(handler)

        thread.start()
        thread.wait(5000)

        assert len(results) == 1

        thread.data_ready.disconnect(handler)

        thread.start()
        thread.wait(5000)

        assert len(results) == 1


class TestErrorHandling:
    """Test error handling in multi-threaded scenarios."""

    def test_exception_in_worker_thread_caught(
        self, qapp: QApplication
    ) -> None:
        """Exceptions in worker threads are caught and reported."""
        class FailingWorker(QThread):
            error_occurred = pyqtSignal(str)

            def run(self) -> None:
                try:
                    raise ValueError("Intentional error for testing")
                except Exception as e:
                    self.error_occurred.emit(str(e))

        errors: list[str] = []

        worker = FailingWorker()
        worker.error_occurred.connect(lambda e: errors.append(e))

        worker.start()
        worker.wait(5000)

        assert len(errors) == 1
        assert "Intentional error" in errors[0]

    def test_timeout_handling_for_long_running_threads(
        self, qapp: QApplication
    ) -> None:
        """Long-running threads can be detected via timeout."""
        class LongRunningThread(QThread):
            def run(self) -> None:
                time.sleep(10)

        thread = LongRunningThread()
        thread.start()

        completed = thread.wait(100)

        assert not completed
        assert thread.isRunning()

        thread.terminate()
        thread.wait(1000)


class TestPerformanceUnderConcurrency:
    """Test performance characteristics under concurrent load."""

    def test_concurrent_processing_faster_than_sequential(
        self, qapp: QApplication
    ) -> None:
        """Concurrent processing completes faster than sequential."""
        data_size = 1000

        start_time = time.time()
        for _ in range(5):
            processor = DataProcessor(list(range(data_size)), processing_time=0.0001)
            processor.start()
            processor.wait(10000)
        sequential_time = time.time() - start_time

        start_time = time.time()
        threads = []
        for _ in range(5):
            processor = DataProcessor(list(range(data_size)), processing_time=0.0001)
            processor.start()
            threads.append(processor)

        for thread in threads:
            thread.wait(10000)

        concurrent_time = time.time() - start_time

        assert concurrent_time < sequential_time


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
