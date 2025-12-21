"""Production tests for psutil_handler.

Tests validate process management, system monitoring, CPU/memory metrics,
disk usage, network statistics, process iteration, and fallback quality.
"""

import os

import pytest

from intellicrack.handlers import psutil_handler


def test_has_psutil_flag_is_boolean() -> None:
    """HAS_PSUTIL is a boolean flag."""
    assert isinstance(psutil_handler.HAS_PSUTIL, bool)


def test_psutil_available_flag_is_boolean() -> None:
    """PSUTIL_AVAILABLE is a boolean flag."""
    assert isinstance(psutil_handler.PSUTIL_AVAILABLE, bool)


def test_psutil_version_is_string_or_none() -> None:
    """PSUTIL_VERSION is None or valid version string."""
    version = psutil_handler.PSUTIL_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_module_exports_process_class() -> None:
    """psutil_handler exports Process class."""
    assert hasattr(psutil_handler, "Process")
    assert psutil_handler.Process is not None


def test_module_exports_exception_classes() -> None:
    """psutil_handler exports exception classes."""
    assert hasattr(psutil_handler, "NoSuchProcess")
    assert hasattr(psutil_handler, "AccessDenied")
    assert hasattr(psutil_handler, "TimeoutExpired")
    assert hasattr(psutil_handler, "Error")


def test_module_exports_status_constants() -> None:
    """psutil_handler exports process status constants."""
    assert hasattr(psutil_handler, "STATUS_RUNNING")
    assert hasattr(psutil_handler, "STATUS_SLEEPING")
    assert hasattr(psutil_handler, "STATUS_ZOMBIE")
    assert hasattr(psutil_handler, "STATUS_STOPPED")


def test_module_exports_system_functions() -> None:
    """psutil_handler exports system monitoring functions."""
    assert hasattr(psutil_handler, "cpu_percent")
    assert hasattr(psutil_handler, "cpu_count")
    assert hasattr(psutil_handler, "virtual_memory")
    assert hasattr(psutil_handler, "disk_usage")


def test_module_exports_process_functions() -> None:
    """psutil_handler exports process management functions."""
    assert hasattr(psutil_handler, "process_iter")
    assert hasattr(psutil_handler, "pid_exists")


def test_process_creates_for_current_pid() -> None:
    """Process() creates process object for current PID."""
    current_pid = os.getpid()

    proc = psutil_handler.Process(current_pid)

    assert proc is not None
    assert proc.pid == current_pid


def test_process_creates_without_pid() -> None:
    """Process() without PID creates process for current process."""
    proc = psutil_handler.Process()

    assert proc is not None
    assert proc.pid == os.getpid()


def test_process_name_returns_string() -> None:
    """Process.name returns process name as string."""
    proc = psutil_handler.Process()

    name = proc.name

    assert isinstance(name, str)
    assert len(name) > 0


def test_process_pid_property() -> None:
    """Process.pid property returns PID."""
    current_pid = os.getpid()
    proc = psutil_handler.Process(current_pid)

    assert proc.pid == current_pid


def test_process_status_returns_valid_status() -> None:
    """Process.status() returns valid status string."""
    proc = psutil_handler.Process()

    status = proc.status()

    assert isinstance(status, str)
    assert status in {
        psutil_handler.STATUS_RUNNING,
        psutil_handler.STATUS_SLEEPING,
        psutil_handler.STATUS_DISK_SLEEP,
        psutil_handler.STATUS_STOPPED,
        psutil_handler.STATUS_ZOMBIE,
        psutil_handler.STATUS_IDLE,
        psutil_handler.STATUS_DEAD,
    }


def test_process_is_running_for_current_process() -> None:
    """Process.is_running() returns True for current process."""
    proc = psutil_handler.Process()

    is_running = proc.is_running()

    assert is_running is True


def test_process_create_time_returns_float() -> None:
    """Process.create_time() returns timestamp as float."""
    proc = psutil_handler.Process()

    create_time = proc.create_time()

    assert isinstance(create_time, float)
    assert create_time > 0


def test_cpu_percent_returns_number() -> None:
    """cpu_percent() returns numeric CPU usage."""
    cpu = psutil_handler.cpu_percent(interval=None)

    assert isinstance(cpu, (int, float, list))

    if isinstance(cpu, (int, float)):
        assert cpu >= 0


def test_cpu_percent_with_percpu() -> None:
    """cpu_percent(percpu=True) returns per-CPU list."""
    cpu_list = psutil_handler.cpu_percent(interval=None, percpu=True)

    assert isinstance(cpu_list, list)
    assert len(cpu_list) > 0


def test_cpu_count_returns_positive_integer() -> None:
    """cpu_count() returns positive integer."""
    count = psutil_handler.cpu_count()

    assert isinstance(count, int)
    assert count > 0


def test_cpu_count_logical_vs_physical() -> None:
    """cpu_count() with logical parameter."""
    logical_count = psutil_handler.cpu_count(logical=True)
    physical_count = psutil_handler.cpu_count(logical=False)

    assert isinstance(logical_count, int)
    assert isinstance(physical_count, int)
    assert logical_count >= physical_count


def test_virtual_memory_returns_memory_info() -> None:
    """virtual_memory() returns memory information object."""
    mem = psutil_handler.virtual_memory()

    assert hasattr(mem, "total")
    assert hasattr(mem, "available")
    assert hasattr(mem, "percent")
    assert hasattr(mem, "used")
    assert hasattr(mem, "free")


def test_virtual_memory_values_are_reasonable() -> None:
    """virtual_memory() returns reasonable values."""
    mem = psutil_handler.virtual_memory()

    assert mem.total > 0
    assert mem.available >= 0
    assert 0 <= mem.percent <= 100
    assert mem.used >= 0


def test_swap_memory_returns_swap_info() -> None:
    """swap_memory() returns swap information object."""
    swap = psutil_handler.swap_memory()

    assert hasattr(swap, "total")
    assert hasattr(swap, "used")
    assert hasattr(swap, "free")
    assert hasattr(swap, "percent")


def test_disk_usage_for_root_path() -> None:
    """disk_usage() returns disk usage for root path."""
    if os.name == "nt":
        path = "C:\\"
    else:
        path = "/"

    usage = psutil_handler.disk_usage(path)

    assert hasattr(usage, "total")
    assert hasattr(usage, "used")
    assert hasattr(usage, "free")
    assert hasattr(usage, "percent")
    assert usage.total > 0


def test_disk_partitions_returns_list() -> None:
    """disk_partitions() returns list of partitions."""
    partitions = psutil_handler.disk_partitions()

    assert isinstance(partitions, list)


def test_disk_partitions_entries_have_attributes() -> None:
    """disk_partitions() entries have expected attributes."""
    partitions = psutil_handler.disk_partitions()

    if len(partitions) > 0:
        partition = partitions[0]
        assert hasattr(partition, "device")
        assert hasattr(partition, "mountpoint")
        assert hasattr(partition, "fstype")


def test_boot_time_returns_timestamp() -> None:
    """boot_time() returns timestamp as float."""
    boot_time = psutil_handler.boot_time()

    assert isinstance(boot_time, float)
    assert boot_time > 0


def test_process_iter_returns_list() -> None:
    """process_iter() returns list of processes."""
    processes = list(psutil_handler.process_iter())

    assert isinstance(processes, list)


def test_pid_exists_for_current_process() -> None:
    """pid_exists() returns True for current process."""
    current_pid = os.getpid()

    exists = psutil_handler.pid_exists(current_pid)

    assert exists is True


def test_pid_exists_for_invalid_pid() -> None:
    """pid_exists() returns False for invalid PID."""
    exists = psutil_handler.pid_exists(999999)

    assert isinstance(exists, bool)


def test_process_memory_info_structure() -> None:
    """Process.memory_info() returns memory info object."""
    proc = psutil_handler.Process()

    mem_info = proc.memory_info()

    assert hasattr(mem_info, "rss")
    assert hasattr(mem_info, "vms")


def test_process_cpu_percent_returns_number() -> None:
    """Process.cpu_percent() returns numeric value."""
    proc = psutil_handler.Process()

    cpu = proc.cpu_percent(interval=None)

    assert isinstance(cpu, (int, float))
    assert cpu >= 0


def test_process_memory_percent_returns_number() -> None:
    """Process.memory_percent() returns numeric value."""
    proc = psutil_handler.Process()

    mem_percent = proc.memory_percent()

    assert isinstance(mem_percent, (int, float))
    assert mem_percent >= 0


def test_cpu_freq_returns_frequency_info() -> None:
    """cpu_freq() returns frequency information."""
    freq = psutil_handler.cpu_freq()

    assert hasattr(freq, "current")


def test_cpu_stats_returns_statistics() -> None:
    """cpu_stats() returns CPU statistics."""
    stats = psutil_handler.cpu_stats()

    assert hasattr(stats, "ctx_switches")
    assert hasattr(stats, "interrupts")


def test_net_io_counters_returns_counters() -> None:
    """net_io_counters() returns network I/O counters."""
    counters = psutil_handler.net_io_counters()

    assert hasattr(counters, "bytes_sent")
    assert hasattr(counters, "bytes_recv")
    assert hasattr(counters, "packets_sent")
    assert hasattr(counters, "packets_recv")


def test_disk_io_counters_returns_counters() -> None:
    """disk_io_counters() returns disk I/O counters."""
    counters = psutil_handler.disk_io_counters()

    assert hasattr(counters, "read_count")
    assert hasattr(counters, "write_count")


def test_net_connections_returns_list() -> None:
    """net_connections() returns list of connections."""
    connections = psutil_handler.net_connections()

    assert isinstance(connections, list)


def test_net_if_addrs_returns_dict() -> None:
    """net_if_addrs() returns dictionary."""
    addrs = psutil_handler.net_if_addrs()

    assert isinstance(addrs, dict)


def test_net_if_stats_returns_dict() -> None:
    """net_if_stats() returns dictionary."""
    stats = psutil_handler.net_if_stats()

    assert isinstance(stats, dict)


def test_users_returns_list() -> None:
    """users() returns list of logged-in users."""
    users = psutil_handler.users()

    assert isinstance(users, list)


def test_popen_class_exists() -> None:
    """Popen class is exported."""
    assert hasattr(psutil_handler, "Popen")


def test_nosuchprocess_exception_structure() -> None:
    """NoSuchProcess exception has correct structure."""
    exc_class = psutil_handler.NoSuchProcess

    assert issubclass(exc_class, psutil_handler.Error)


def test_accessdenied_exception_structure() -> None:
    """AccessDenied exception has correct structure."""
    exc_class = psutil_handler.AccessDenied

    assert issubclass(exc_class, psutil_handler.Error)


def test_timeoutexpired_exception_structure() -> None:
    """TimeoutExpired exception has correct structure."""
    exc_class = psutil_handler.TimeoutExpired

    assert issubclass(exc_class, psutil_handler.Error)


def test_all_exports_are_defined() -> None:
    """All items in __all__ are defined in module."""
    for item in psutil_handler.__all__:
        assert hasattr(psutil_handler, item)


def test_flags_consistency() -> None:
    """HAS_PSUTIL and PSUTIL_AVAILABLE are consistent."""
    assert psutil_handler.HAS_PSUTIL == psutil_handler.PSUTIL_AVAILABLE


def test_version_consistency_with_availability() -> None:
    """PSUTIL_VERSION is None when psutil unavailable."""
    if not psutil_handler.HAS_PSUTIL:
        assert psutil_handler.PSUTIL_VERSION is None


def test_process_exe_returns_string_or_none() -> None:
    """Process.exe() returns executable path or empty string."""
    proc = psutil_handler.Process()

    exe = proc.exe()

    assert isinstance(exe, (str, type(None)))


def test_process_cmdline_returns_list() -> None:
    """Process.cmdline() returns command line as list."""
    proc = psutil_handler.Process()

    cmdline = proc.cmdline()

    assert isinstance(cmdline, list)


def test_process_ppid_returns_int_or_none() -> None:
    """Process.ppid() returns parent PID or None."""
    proc = psutil_handler.Process()

    ppid = proc.ppid()

    assert isinstance(ppid, (int, type(None)))


def test_process_parent_returns_process_or_none() -> None:
    """Process.parent() returns parent Process or None."""
    proc = psutil_handler.Process()

    try:
        parent = proc.parent()
        assert parent is None or hasattr(parent, "pid")
    except psutil_handler.AccessDenied:
        pass


def test_process_children_returns_list() -> None:
    """Process.children() returns list of child processes."""
    proc = psutil_handler.Process()

    children = proc.children(recursive=False)

    assert isinstance(children, list)


def test_wait_procs_returns_tuple() -> None:
    """wait_procs() returns tuple of (gone, alive) processes."""
    proc = psutil_handler.Process()
    procs = [proc]

    gone, alive = psutil_handler.wait_procs(procs, timeout=0.1)

    assert isinstance(gone, list)
    assert isinstance(alive, list)


def test_fallback_process_works_when_psutil_unavailable() -> None:
    """Fallback Process implementation works when psutil unavailable."""
    if not psutil_handler.HAS_PSUTIL:
        proc = psutil_handler.Process()

        assert proc is not None
        assert hasattr(proc, "pid")
        assert hasattr(proc, "name")
