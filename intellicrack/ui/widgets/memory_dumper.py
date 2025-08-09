"""Memory dumper widget for process memory analysis.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import platform

from intellicrack.ui.dialogs.common_imports import (
    QCheckBox, QComboBox, QFileDialog, QGroupBox,
    QHBoxLayout, QLabel, QProgressBar, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit,
    QThread, QVBoxLayout, QWidget, pyqtSignal,
)


class MemoryDumperWidget(QWidget):
    """Widget for dumping and analyzing process memory."""

    def __init__(self, parent=None):
        """Initialize memory dumper widget with parent widget and process tracking components."""
        super().__init__(parent)
        self.current_process = None
        self.dump_thread = None
        self.setup_ui()

    def setup_ui(self):
        """Set up the memory dumper UI."""
        layout = QVBoxLayout(self)

        # Title
        title = QLabel("<h2>Memory Dump Tool</h2>")
        layout.addWidget(title)

        # Process selection
        process_group = QGroupBox("Process Selection")
        process_layout = QVBoxLayout(process_group)

        # Process list controls
        process_controls = QHBoxLayout()

        self.process_combo = QComboBox()
        self.process_combo.setEditable(True)
        self.process_combo.setPlaceholderText("Select process or enter PID")
        process_controls.addWidget(self.process_combo)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_process_list)
        process_controls.addWidget(refresh_btn)

        attach_btn = QPushButton("Attach")
        attach_btn.clicked.connect(self.attach_to_process)
        process_controls.addWidget(attach_btn)

        process_layout.addLayout(process_controls)

        # Process info
        self.process_info = QLabel("No process attached")
        process_layout.addWidget(self.process_info)

        layout.addWidget(process_group)

        # Memory regions
        regions_group = QGroupBox("Memory Regions")
        regions_layout = QVBoxLayout(regions_group)

        # Region filters
        filter_layout = QHBoxLayout()

        self.readable_check = QCheckBox("Readable")
        self.readable_check.setChecked(True)
        self.writable_check = QCheckBox("Writable")
        self.writable_check.setChecked(True)
        self.executable_check = QCheckBox("Executable")
        self.private_check = QCheckBox("Private")
        self.private_check.setChecked(True)

        filter_layout.addWidget(self.readable_check)
        filter_layout.addWidget(self.writable_check)
        filter_layout.addWidget(self.executable_check)
        filter_layout.addWidget(self.private_check)
        filter_layout.addStretch()

        regions_layout.addLayout(filter_layout)

        # Regions table
        self.regions_table = QTableWidget()
        self.regions_table.setColumnCount(5)
        self.regions_table.setHorizontalHeaderLabels(
            ["Address", "Size", "Protection", "Type", "Path"]
        )
        self.regions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        regions_layout.addWidget(self.regions_table)

        # Region controls
        region_controls = QHBoxLayout()

        scan_regions_btn = QPushButton("Scan Regions")
        scan_regions_btn.clicked.connect(self.scan_memory_regions)
        region_controls.addWidget(scan_regions_btn)

        dump_selected_btn = QPushButton("Dump Selected")
        dump_selected_btn.clicked.connect(self.dump_selected_regions)
        region_controls.addWidget(dump_selected_btn)

        dump_all_btn = QPushButton("Dump All")
        dump_all_btn.clicked.connect(self.dump_all_regions)
        region_controls.addWidget(dump_all_btn)

        region_controls.addStretch()
        regions_layout.addLayout(region_controls)

        layout.addWidget(regions_group)

        # Dump options
        options_group = QGroupBox("Dump Options")
        options_layout = QVBoxLayout(options_group)

        # Format options
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))

        self.raw_dump_check = QCheckBox("Raw")
        self.raw_dump_check.setChecked(True)
        self.minidump_check = QCheckBox("MiniDump")
        self.full_dump_check = QCheckBox("Full Dump")

        format_layout.addWidget(self.raw_dump_check)
        format_layout.addWidget(self.minidump_check)
        format_layout.addWidget(self.full_dump_check)
        format_layout.addStretch()

        options_layout.addLayout(format_layout)

        # Additional options
        extra_options = QHBoxLayout()

        self.compress_check = QCheckBox("Compress")
        self.metadata_check = QCheckBox("Include Metadata")
        self.metadata_check.setChecked(True)
        self.strings_check = QCheckBox("Extract Strings")

        extra_options.addWidget(self.compress_check)
        extra_options.addWidget(self.metadata_check)
        extra_options.addWidget(self.strings_check)
        extra_options.addStretch()

        options_layout.addLayout(extra_options)

        layout.addWidget(options_group)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Output log
        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setMaximumHeight(150)
        layout.addWidget(self.output_log)

        # Initial refresh
        self.refresh_process_list()

    def refresh_process_list(self):
        """Refresh the list of running processes."""
        self.process_combo.clear()

        if platform.system() == "Windows":
            self._refresh_windows_processes()
        else:
            self._refresh_linux_processes()

    def _refresh_windows_processes(self):
        """Refresh Windows process list."""
        try:
            import psutil

            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    info = proc.info
                    self.process_combo.addItem(f"{info['name']} (PID: {info['pid']})", info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except ImportError:
            self.output_log.append("psutil not installed. Using basic process enumeration.")
            # Fallback to WMI or basic enumeration
            try:
                import subprocess

                result = subprocess.run(
                    ["tasklist", "/fo", "csv"],
                    check=False,
                    capture_output=True,
                    text=True,  # noqa: S607
                )
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split('","')
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        pid = parts[1].strip('"')
                        self.process_combo.addItem(f"{name} (PID: {pid})", int(pid))
            except Exception as e:
                self.output_log.append(f"Failed to enumerate processes: {e}")

    def _refresh_linux_processes(self):
        """Refresh Linux process list."""
        try:
            import psutil

            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    info = proc.info
                    self.process_combo.addItem(f"{info['name']} (PID: {info['pid']})", info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except ImportError:
            # Fallback to /proc
            try:
                for pid_dir in os.listdir("/proc"):
                    if pid_dir.isdigit():
                        try:
                            with open(f"/proc/{pid_dir}/comm") as f:
                                name = f.read().strip()
                            self.process_combo.addItem(f"{name} (PID: {pid_dir})", int(pid_dir))
                        except:
                            pass
            except Exception as e:
                self.output_log.append(f"Failed to enumerate processes: {e}")

    def attach_to_process(self):
        """Attach to selected process."""
        if self.process_combo.currentData():
            pid = self.process_combo.currentData()
        else:
            try:
                # Try to parse PID from text
                text = self.process_combo.currentText()
                pid = int(text.split("PID: ")[-1].rstrip(")"))
            except:
                self.output_log.append("Invalid process selection")
                return

        self.current_process = pid
        self.process_info.setText(f"Attached to PID: {pid}")
        self.output_log.append(f"Successfully attached to process {pid}")

        # Auto-scan regions
        self.scan_memory_regions()

    def scan_memory_regions(self):
        """Scan memory regions of attached process."""
        if not self.current_process:
            self.output_log.append("No process attached")
            return

        self.regions_table.setRowCount(0)

        if platform.system() == "Windows":
            self._scan_windows_regions()
        else:
            self._scan_linux_regions()

    def _scan_windows_regions(self):
        """Scan Windows process memory regions."""
        try:
            import ctypes
            from ctypes import wintypes

            # Windows API structures
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            # Open process
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            kernel32 = ctypes.windll.kernel32
            h_process = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                self.current_process,
            )

            if not h_process:
                self.output_log.append("Failed to open process")
                return

            # Scan memory regions
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()

            while address < 0x7FFFFFFFFFFFFFFF:  # User space limit
                result = kernel32.VirtualQueryEx(
                    h_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi),
                )

                if result == 0:
                    break

                # Check if region matches filters
                if mbi.State == 0x1000:  # MEM_COMMIT
                    protection = self._get_protection_string(mbi.Protect)
                    region_type = self._get_region_type(mbi.Type)

                    # Apply filters
                    if self._should_include_region(mbi.Protect):
                        row = self.regions_table.rowCount()
                        self.regions_table.insertRow(row)

                        self.regions_table.setItem(
                            row, 0, QTableWidgetItem(f"0x{mbi.BaseAddress:016X}")
                        )
                        self.regions_table.setItem(
                            row, 1, QTableWidgetItem(f"{mbi.RegionSize:,} bytes")
                        )
                        self.regions_table.setItem(row, 2, QTableWidgetItem(protection))
                        self.regions_table.setItem(row, 3, QTableWidgetItem(region_type))
                        self.regions_table.setItem(row, 4, QTableWidgetItem(""))

                address = mbi.BaseAddress + mbi.RegionSize

            kernel32.CloseHandle(h_process)
            self.output_log.append(f"Found {self.regions_table.rowCount()} memory regions")

        except Exception as e:
            self.output_log.append(f"Error scanning regions: {e}")

    def _scan_linux_regions(self):
        """Scan Linux process memory regions."""
        try:
            maps_file = f"/proc/{self.current_process}/maps"
            with open(maps_file) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        # Parse address range
                        addr_range = parts[0].split("-")
                        start_addr = int(addr_range[0], 16)
                        end_addr = int(addr_range[1], 16)
                        size = end_addr - start_addr

                        # Parse permissions
                        perms = parts[1]

                        # Apply filters
                        if self._should_include_region_linux(perms):
                            row = self.regions_table.rowCount()
                            self.regions_table.insertRow(row)

                            self.regions_table.setItem(
                                row, 0, QTableWidgetItem(f"0x{start_addr:016X}")
                            )
                            self.regions_table.setItem(row, 1, QTableWidgetItem(f"{size:,} bytes"))
                            self.regions_table.setItem(row, 2, QTableWidgetItem(perms))
                            self.regions_table.setItem(
                                row, 3, QTableWidgetItem(parts[3] if len(parts) > 3 else "")
                            )
                            self.regions_table.setItem(
                                row, 4, QTableWidgetItem(parts[5] if len(parts) > 5 else "")
                            )

            self.output_log.append(f"Found {self.regions_table.rowCount()} memory regions")

        except Exception as e:
            self.output_log.append(f"Error scanning regions: {e}")

    def _get_protection_string(self, protect):
        """Convert Windows protection flags to string."""
        protections = {
            0x01: "NOACCESS",
            0x02: "READONLY",
            0x04: "READWRITE",
            0x08: "WRITECOPY",
            0x10: "EXECUTE",
            0x20: "EXECUTE_READ",
            0x40: "EXECUTE_READWRITE",
            0x80: "EXECUTE_WRITECOPY",
        }

        base_protect = protect & 0xFF
        return protections.get(base_protect, f"0x{protect:X}")

    def _get_region_type(self, mem_type):
        """Convert Windows memory type to string."""
        types = {
            0x20000: "PRIVATE",
            0x40000: "MAPPED",
            0x1000000: "IMAGE",
        }
        return types.get(mem_type, f"0x{mem_type:X}")

    def _should_include_region(self, protect):
        """Check if Windows region should be included based on filters."""
        # Check protection flags
        readable = protect & 0x66  # Any read permission
        writable = protect & 0x44  # Any write permission
        executable = protect & 0xF0  # Any execute permission

        if self.readable_check.isChecked() and not readable:
            return False
        if self.writable_check.isChecked() and not writable:
            return False
        if self.executable_check.isChecked() and not executable:
            return False

        return True

    def _should_include_region_linux(self, perms):
        """Check if Linux region should be included based on filters."""
        if self.readable_check.isChecked() and "r" not in perms:
            return False
        if self.writable_check.isChecked() and "w" not in perms:
            return False
        if self.executable_check.isChecked() and "x" not in perms:
            return False
        if self.private_check.isChecked() and "p" not in perms:
            return False

        return True

    def dump_selected_regions(self):
        """Dump selected memory regions."""
        selected_rows = set()
        for item in self.regions_table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            self.output_log.append("No regions selected")
            return

        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not output_dir:
            return

        # Start dump thread
        self.dump_thread = MemoryDumpThread(
            self.current_process,
            list(selected_rows),
            self.regions_table,
            output_dir,
            self.get_dump_options(),
        )

        self.dump_thread.progress.connect(self.update_progress)
        self.dump_thread.log.connect(self.output_log.append)
        self.dump_thread.finished.connect(self.dump_finished)

        self.progress_bar.setVisible(True)
        self.dump_thread.start()

    def dump_all_regions(self):
        """Dump all memory regions."""
        if self.regions_table.rowCount() == 0:
            self.output_log.append("No regions to dump")
            return

        # Select all rows
        all_rows = list(range(self.regions_table.rowCount()))

        output_dir = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if not output_dir:
            return

        # Start dump thread
        self.dump_thread = MemoryDumpThread(
            self.current_process,
            all_rows,
            self.regions_table,
            output_dir,
            self.get_dump_options(),
        )

        self.dump_thread.progress.connect(self.update_progress)
        self.dump_thread.log.connect(self.output_log.append)
        self.dump_thread.finished.connect(self.dump_finished)

        self.progress_bar.setVisible(True)
        self.dump_thread.start()

    def get_dump_options(self):
        """Get current dump options."""
        return {
            "raw": self.raw_dump_check.isChecked(),
            "minidump": self.minidump_check.isChecked(),
            "full": self.full_dump_check.isChecked(),
            "compress": self.compress_check.isChecked(),
            "metadata": self.metadata_check.isChecked(),
            "strings": self.strings_check.isChecked(),
        }

    def update_progress(self, value):
        """Update progress bar."""
        self.progress_bar.setValue(value)

    def dump_finished(self):
        """Handle dump completion."""
        self.progress_bar.setVisible(False)
        self.output_log.append("Memory dump completed")


class MemoryDumpThread(QThread):
    """Thread for dumping memory regions."""

    progress = pyqtSignal(int)
    log = pyqtSignal(str)

    def __init__(self, pid, rows, table, output_dir, options):
        """Initialize memory dump thread with process ID, table data, output directory, and dump options."""
        super().__init__()
        self.pid = pid
        self.rows = rows
        self.table = table
        self.output_dir = output_dir
        self.options = options

    def run(self):
        """Execute memory dump."""
        total = len(self.rows)

        for i, row in enumerate(self.rows):
            # Get region info
            addr_text = self.table.item(row, 0).text()
            size_text = self.table.item(row, 1).text()

            addr = int(addr_text, 16)
            size = int(size_text.replace(",", "").replace(" bytes", ""))

            self.log.emit(f"Dumping region 0x{addr:016X} ({size:,} bytes)")

            try:
                if platform.system() == "Windows":
                    self._dump_windows_region(addr, size)
                else:
                    self._dump_linux_region(addr, size)

            except Exception as e:
                self.log.emit(f"Error dumping region: {e}")

            # Update progress
            self.progress.emit(int((i + 1) / total * 100))

    def _dump_windows_region(self, addr, size):
        """Dump Windows memory region."""
        import ctypes

        # Open process
        PROCESS_VM_READ = 0x0010
        kernel32 = ctypes.windll.kernel32

        h_process = kernel32.OpenProcess(PROCESS_VM_READ, False, self.pid)
        if not h_process:
            raise Exception("Failed to open process")

        try:
            # Read memory
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()

            result = kernel32.ReadProcessMemory(
                h_process,
                ctypes.c_void_p(addr),
                buffer,
                size,
                ctypes.byref(bytes_read),
            )

            if result:
                # Save to file
                filename = os.path.join(self.output_dir, f"dump_0x{addr:016X}.bin")
                with open(filename, "wb") as f:
                    f.write(buffer.raw[: bytes_read.value])

                self.log.emit(f"Saved {bytes_read.value:,} bytes to {filename}")

                # Extract strings if requested
                if self.options["strings"]:
                    self._extract_strings(buffer.raw[: bytes_read.value], addr)

            else:
                self.log.emit(f"Failed to read memory at 0x{addr:016X}")

        finally:
            kernel32.CloseHandle(h_process)

    def _dump_linux_region(self, addr, size):
        """Dump Linux memory region."""
        mem_file = f"/proc/{self.pid}/mem"

        try:
            with open(mem_file, "rb") as f:
                f.seek(addr)
                data = f.read(size)

                # Save to file
                filename = os.path.join(self.output_dir, f"dump_0x{addr:016X}.bin")
                with open(filename, "wb") as out:
                    out.write(data)

                self.log.emit(f"Saved {len(data):,} bytes to {filename}")

                # Extract strings if requested
                if self.options["strings"]:
                    self._extract_strings(data, addr)

        except Exception as e:
            self.log.emit(f"Failed to read memory at 0x{addr:016X}: {e}")

    def _extract_strings(self, data, base_addr):
        """Extract printable strings from memory dump."""
        strings = []
        current_string = bytearray()

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(byte)
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(
                        (
                            base_addr + i - len(current_string),
                            current_string.decode("ascii", errors="ignore"),
                        )
                    )
                current_string = bytearray()

        # Save strings to file
        if strings:
            filename = os.path.join(self.output_dir, f"strings_0x{base_addr:016X}.txt")
            with open(filename, "w", encoding="utf-8") as f:
                f.writelines(f"0x{addr:016X}: {string}\n" for addr, string in strings)

            self.log.emit(f"Extracted {len(strings)} strings to {filename}")
