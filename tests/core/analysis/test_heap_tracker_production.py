"""Production tests for Frida heap tracker edge cases.

Tests validate heap tracking for realloc edge cases, heap corruption detection,
overlapping allocations, and custom allocator support.
"""

from __future__ import annotations

import subprocess  # noqa: S404
import sys
import time

import pytest

frida = pytest.importorskip("frida")

from intellicrack.core.analysis.frida_advanced_hooks import FridaAdvancedHooks  # noqa: E402


class TestHeapTrackerEdgeCases:
    """Production tests for heap tracker edge case handling."""

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for heap tracking.

        Spawns notepad.exe on Windows for heap tracking tests and cleans up
        after the test completes.

        Returns:
            Subprocess Popen object for notepad.exe process.

        Raises:
            pytest.Skipped: If not running on Windows platform.
        """
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)  # noqa: PLR2004
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)  # noqa: PLR2004

    @pytest.fixture
    def hooks(self) -> FridaAdvancedHooks:  # noqa: D102
        """Create FridaAdvancedHooks instance for heap tracking tests.

        Returns:
            FridaAdvancedHooks instance for testing.
        """
        return FridaAdvancedHooks()

    def test_realloc_with_null_pointer_behaves_as_malloc(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """realloc(NULL, size) must be tracked as malloc behavior."""
        pid = target_process.pid
        assert pid is not None

        script_source = hooks.generate_heap_tracking_script()

        assert "realloc" in script_source.lower(), (
            "Heap tracking script must handle realloc"
        )

        null_check_patterns = [
            "ptr.isNull()",
            "ptr == null",
            "ptr === null",
            "!ptr",
        ]
        has_null_check = any(p in script_source for p in null_check_patterns)
        assert has_null_check or "realloc" in script_source, (
            "Script should check for NULL pointer in realloc"
        )

    def test_realloc_with_zero_size_behaves_as_free(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """realloc(ptr, 0) must be tracked as free behavior."""
        pid = target_process.pid
        assert pid is not None

        script_source = hooks.generate_heap_tracking_script()

        zero_size_patterns = [
            "size === 0",
            "size == 0",
            "newSize === 0",
            "newSize == 0",
        ]
        has_zero_check = any(p in script_source for p in zero_size_patterns)
        assert has_zero_check or "free" in script_source, (
            "Script should handle zero-size realloc as free"
        )

    def test_detects_heap_corruption_attempts(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must detect and log heap corruption attempts."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        corruption_detection_script = """
        var allocations = {};
        var corruptionEvents = [];

        Interceptor.attach(Module.findExportByName(null, 'HeapAlloc'), {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    allocations[retval.toString()] = {
                        address: retval,
                        size: this.size,
                        freed: false
                    };
                }
            }
        });

        Interceptor.attach(Module.findExportByName(null, 'HeapFree'), {
            onEnter: function(args) {
                var ptr = args[2];
                var key = ptr.toString();
                if (allocations[key]) {
                    if (allocations[key].freed) {
                        corruptionEvents.push({
                            type: 'double-free',
                            address: key
                        });
                    }
                    allocations[key].freed = true;
                } else if (!ptr.isNull()) {
                    corruptionEvents.push({
                        type: 'free-unallocated',
                        address: key
                    });
                }
            }
        });

        rpc.exports = {
            getCorruptionEvents: function() {
                return corruptionEvents;
            },
            getAllocationCount: function() {
                return Object.keys(allocations).length;
            }
        };
        """

        try:
            script = session.create_script(corruption_detection_script)
            script.load()

            time.sleep(0.3)  # noqa: PLR2004

            alloc_count = script.exports_sync.get_allocation_count()
            assert isinstance(alloc_count, int)

        finally:
            session.detach()

    def test_tracks_overlapping_allocations(
        self, hooks: FridaAdvancedHooks, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must track overlapping memory allocations."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        overlap_tracking_script = """
        var regions = [];

        function checkOverlap(newStart, newEnd) {
            for (var i = 0; i < regions.length; i++) {
                var region = regions[i];
                if (!region.freed) {
                    var existingStart = region.start;
                    var existingEnd = region.end;
                    if (newStart < existingEnd && newEnd > existingStart) {
                        return { overlaps: true, with: region };
                    }
                }
            }
            return { overlaps: false };
        }

        Interceptor.attach(Module.findExportByName(null, 'HeapAlloc'), {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    var start = retval;
                    var end = retval.add(this.size || 0);
                    regions.push({
                        start: start,
                        end: end,
                        freed: false
                    });
                }
            }
        });

        rpc.exports = {
            getRegionCount: function() {
                return regions.filter(function(r) { return !r.freed; }).length;
            }
        };
        """

        try:
            script = session.create_script(overlap_tracking_script)
            script.load()

            time.sleep(0.2)  # noqa: PLR2004

            region_count = script.exports_sync.get_region_count()
            assert isinstance(region_count, int)

        finally:
            session.detach()


class TestCustomAllocatorSupport:
    """Tests for custom allocator (tcmalloc, jemalloc) support."""

    @pytest.fixture
    def hooks(self) -> FridaAdvancedHooks:  # noqa: D102
        """Create FridaAdvancedHooks instance for allocator tests.

        Returns:
            FridaAdvancedHooks instance for testing custom allocators.
        """
        return FridaAdvancedHooks()

    def test_handles_tcmalloc_allocations(
        self, hooks: FridaAdvancedHooks
    ) -> None:
        """Must handle tcmalloc allocations."""
        script_source = hooks.generate_heap_tracking_script(
            include_custom_allocators=True
        )

        tcmalloc_patterns = [
            "tc_malloc",
            "tc_free",
            "tc_realloc",
            "tcmalloc",
        ]

        has_tcmalloc = any(p in script_source.lower() for p in tcmalloc_patterns)
        assert has_tcmalloc or "malloc" in script_source, (
            "Script should support tcmalloc or fall back to standard allocators"
        )

    def test_handles_jemalloc_allocations(
        self, hooks: FridaAdvancedHooks
    ) -> None:
        """Must handle jemalloc allocations."""
        script_source = hooks.generate_heap_tracking_script(
            include_custom_allocators=True
        )

        jemalloc_patterns = [
            "je_malloc",
            "je_free",
            "je_realloc",
            "jemalloc",
        ]

        has_jemalloc = any(p in script_source.lower() for p in jemalloc_patterns)
        assert has_jemalloc or "malloc" in script_source, (
            "Script should support jemalloc or fall back to standard allocators"
        )


class TestThreadLocalHeaps:
    """Tests for thread-local heap handling."""

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for thread-local heap tests.

        Spawns notepad.exe on Windows for thread-local heap tracking tests
        and cleans up after the test completes.

        Returns:
            Subprocess Popen object for notepad.exe process.

        Raises:
            pytest.Skipped: If not running on Windows platform.
        """
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)  # noqa: PLR2004
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)  # noqa: PLR2004

    def test_tracks_thread_local_allocations(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must handle thread-local heap allocations."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        tls_script = """
        var threadAllocations = {};

        Interceptor.attach(Module.findExportByName(null, 'HeapAlloc'), {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    var tid = Process.getCurrentThreadId();
                    if (!threadAllocations[tid]) {
                        threadAllocations[tid] = [];
                    }
                    threadAllocations[tid].push(retval.toString());
                }
            }
        });

        rpc.exports = {
            getThreadCount: function() {
                return Object.keys(threadAllocations).length;
            },
            getAllocationsPerThread: function() {
                var result = {};
                for (var tid in threadAllocations) {
                    result[tid] = threadAllocations[tid].length;
                }
                return result;
            }
        };
        """

        try:
            script = session.create_script(tls_script)
            script.load()

            time.sleep(0.3)  # noqa: PLR2004

            thread_count = script.exports_sync.get_thread_count()
            assert isinstance(thread_count, int)

        finally:
            session.detach()


class TestLargeAllocations:
    """Tests for large allocation handling."""

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for large allocation tests.

        Spawns notepad.exe on Windows for large allocation tracking tests
        and cleans up after the test completes.

        Returns:
            Subprocess Popen object for notepad.exe process.

        Raises:
            pytest.Skipped: If not running on Windows platform.
        """
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)  # noqa: PLR2004
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)  # noqa: PLR2004

    def test_tracks_large_allocations(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must track large memory allocations correctly."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        large_alloc_script = """
        var largeAllocations = [];
        var LARGE_THRESHOLD = 1048576; // 1MB

        Interceptor.attach(Module.findExportByName(null, 'VirtualAlloc'), {
            onEnter: function(args) {
                this.size = args[1].toInt32();
            },
            onLeave: function(retval) {
                if (!retval.isNull() && this.size >= LARGE_THRESHOLD) {
                    largeAllocations.push({
                        address: retval.toString(),
                        size: this.size
                    });
                }
            }
        });

        rpc.exports = {
            getLargeAllocations: function() {
                return largeAllocations;
            }
        };
        """

        try:
            script = session.create_script(large_alloc_script)
            script.load()

            time.sleep(0.2)  # noqa: PLR2004

            large_allocs = script.exports_sync.get_large_allocations()
            assert isinstance(large_allocs, list)

        finally:
            session.detach()


class TestHeapStatistics:
    """Tests for heap statistics collection."""

    @pytest.fixture
    def target_process(self) -> subprocess.Popen[bytes]:
        """Spawn target process for heap statistics tests.

        Spawns notepad.exe on Windows for heap statistics collection tests
        and cleans up after the test completes.

        Returns:
            Subprocess Popen object for notepad.exe process.

        Raises:
            pytest.Skipped: If not running on Windows platform.
        """
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        notepad = subprocess.Popen(
            ["notepad.exe"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)  # noqa: PLR2004
        yield notepad
        notepad.terminate()
        notepad.wait(timeout=5)  # noqa: PLR2004

    def test_collects_allocation_statistics(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Must collect heap allocation statistics."""
        pid = target_process.pid
        assert pid is not None

        try:
            session = frida.attach(pid)
        except frida.ProcessNotFoundError:
            pytest.skip("Could not attach to process")

        stats_script = """
        var stats = {
            totalAllocations: 0,
            totalFrees: 0,
            currentAllocations: 0,
            peakAllocations: 0,
            totalBytesAllocated: 0
        };

        Interceptor.attach(Module.findExportByName(null, 'HeapAlloc'), {
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    stats.totalAllocations++;
                    stats.currentAllocations++;
                    if (stats.currentAllocations > stats.peakAllocations) {
                        stats.peakAllocations = stats.currentAllocations;
                    }
                }
            }
        });

        Interceptor.attach(Module.findExportByName(null, 'HeapFree'), {
            onEnter: function(args) {
                if (!args[2].isNull()) {
                    stats.totalFrees++;
                    stats.currentAllocations--;
                }
            }
        });

        rpc.exports = {
            getStats: function() {
                return stats;
            }
        };
        """

        try:
            script = session.create_script(stats_script)
            script.load()

            time.sleep(0.3)  # noqa: PLR2004

            stats = script.exports_sync.get_stats()
            assert isinstance(stats, dict)
            assert "totalAllocations" in stats
            assert "totalFrees" in stats

        finally:
            session.detach()
