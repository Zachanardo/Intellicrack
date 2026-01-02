"""Adobe Injector Tab - Native integration without Python conversion.

This module provides multiple integration methods for Adobe Injector
without converting the AutoIt3 code to Python.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import json
import logging
import pathlib
import subprocess
import threading
from typing import Any

from intellicrack.core.adobe_injector_integration import AdobeInjectorWidget
from intellicrack.core.terminal_manager import get_terminal_manager
from intellicrack.handlers.pyqt6_handler import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.ui.tabs.base_tab import BaseTab
from intellicrack.utils.path_resolver import get_project_root


logger = logging.getLogger(__name__)


class AdobeInjectorTab(BaseTab):
    """Adobe Injector tab with multiple integration methods."""

    injector_started = pyqtSignal(str)
    patch_completed = pyqtSignal(bool, str)

    def __init__(self, shared_context: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
        """Initialize Adobe Injector tab.

        Args:
            shared_context: Shared application context dictionary containing
                app_context, task_manager, and main_window.
            parent: Parent QWidget for this tab.

        """
        self.adobe_injector_process: subprocess.Popen[bytes] | None = None
        self.integration_method: str = "embedded"
        self.method_combo: QComboBox | None = None
        self.method_tabs: QTabWidget | None = None
        self.embedded_widget: AdobeInjectorWidget | None = None
        self.cmd_args: QLineEdit | None = None
        self.subprocess_output: QTextEdit | None = None
        self.terminal_cmd: QLineEdit | None = None
        self.terminal_display: QTextEdit | None = None
        super().__init__(shared_context, parent)

    def setup_content(self) -> None:
        """Set up the Adobe Injector tab content."""
        layout = self.layout()
        if layout is None:
            layout = QVBoxLayout(self)

        method_group = QGroupBox("Integration Method")
        method_layout = QHBoxLayout(method_group)

        method_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(
            [
                "Embedded Window (Native)",
                "Subprocess Control",
                "Terminal Execution",
                "DLL Injection",
                "AutoIt3X COM",
            ],
        )
        self.method_combo.currentTextChanged.connect(self.on_method_changed)

        method_layout.addWidget(self.method_combo)
        method_layout.addWidget(QLabel("Choose how to integrate Adobe Injector"))
        method_layout.addStretch()

        layout.addWidget(method_group)

        self.method_tabs = QTabWidget()
        self.method_tabs.addTab(self.create_embedded_tab(), "Embedded")
        self.method_tabs.addTab(self.create_subprocess_tab(), "Subprocess")
        self.method_tabs.addTab(self.create_terminal_tab(), "Terminal")
        self.method_tabs.addTab(self.create_advanced_tab(), "Advanced")

        layout.addWidget(self.method_tabs)

    def create_embedded_tab(self) -> QWidget:
        """Create embedded window integration tab.

        Returns:
            A tab widget containing the embedded Adobe Injector widget.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.embedded_widget = AdobeInjectorWidget()
        if hasattr(self.embedded_widget, "status_updated"):
            self.embedded_widget.status_updated.connect(self.on_status_update)
        layout.addWidget(self.embedded_widget)

        return tab

    def create_subprocess_tab(self) -> QWidget:
        """Create subprocess control tab.

        Returns:
            A tab widget for controlling Adobe Injector via subprocess.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        control_group = QGroupBox("Subprocess Control")
        control_layout = QVBoxLayout(control_group)

        cmd_layout = QHBoxLayout()
        cmd_layout.addWidget(QLabel("Arguments:"))
        self.cmd_args = QLineEdit()
        self.cmd_args.setText("/silent /path:C:\\Program Files\\Adobe")
        cmd_layout.addWidget(self.cmd_args)

        control_layout.addLayout(cmd_layout)

        btn_layout = QHBoxLayout()

        launch_hidden_btn = QPushButton("Launch Hidden")
        launch_hidden_btn.clicked.connect(lambda: self.launch_subprocess(True))
        launch_hidden_btn.setStyleSheet("font-weight: bold; color: blue;")

        launch_visible_btn = QPushButton("Launch Visible")
        launch_visible_btn.clicked.connect(lambda: self.launch_subprocess(False))
        launch_visible_btn.setStyleSheet("font-weight: bold; color: green;")

        monitor_btn = QPushButton("Monitor Output")
        monitor_btn.clicked.connect(self.monitor_subprocess)

        btn_layout.addWidget(launch_hidden_btn)
        btn_layout.addWidget(launch_visible_btn)
        btn_layout.addWidget(monitor_btn)

        control_layout.addLayout(btn_layout)
        layout.addWidget(control_group)

        output_group = QGroupBox("Process Output")
        output_layout = QVBoxLayout(output_group)

        self.subprocess_output = QTextEdit()
        self.subprocess_output.setReadOnly(True)
        output_layout.addWidget(self.subprocess_output)

        layout.addWidget(output_group)

        return tab

    def create_terminal_tab(self) -> QWidget:
        """Create terminal execution tab.

        Returns:
            A tab widget for executing commands in embedded terminal.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        terminal_group = QGroupBox("Terminal Execution")
        terminal_layout = QVBoxLayout(terminal_group)

        btn_layout = QHBoxLayout()

        scan_btn = QPushButton("Scan Adobe Products")
        scan_btn.clicked.connect(self.scan_in_terminal)
        scan_btn.setStyleSheet("font-weight: bold; color: blue;")

        patch_btn = QPushButton("Apply Patches")
        patch_btn.clicked.connect(self.patch_in_terminal)
        patch_btn.setStyleSheet("font-weight: bold; color: green;")

        custom_btn = QPushButton("Custom Command")
        custom_btn.clicked.connect(self.custom_terminal_command)

        btn_layout.addWidget(scan_btn)
        btn_layout.addWidget(patch_btn)
        btn_layout.addWidget(custom_btn)

        terminal_layout.addLayout(btn_layout)

        cmd_builder_layout = QHBoxLayout()
        cmd_builder_layout.addWidget(QLabel("Command:"))
        self.terminal_cmd = QLineEdit()
        self.terminal_cmd.setText("AdobeInjector.exe")
        cmd_builder_layout.addWidget(self.terminal_cmd)

        execute_btn = QPushButton("Execute")
        execute_btn.clicked.connect(self.execute_terminal_command)
        cmd_builder_layout.addWidget(execute_btn)

        terminal_layout.addLayout(cmd_builder_layout)
        layout.addWidget(terminal_group)

        terminal_output = QGroupBox("Terminal Output")
        terminal_output_layout = QVBoxLayout(terminal_output)

        self.terminal_display = QTextEdit()
        self.terminal_display.setReadOnly(True)
        self.terminal_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: Consolas, monospace;
                font-size: 10pt;
                border: 1px solid #444;
            }
        """)
        terminal_output_layout.addWidget(self.terminal_display)

        layout.addWidget(terminal_output)

        return tab

    def create_advanced_tab(self) -> QWidget:
        """Create advanced integration options tab.

        Returns:
            A tab widget for advanced Adobe Injector options including DLL
            compilation, COM interface, resources, and silent configuration.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        dll_group = QGroupBox("DLL Compilation")
        dll_layout = QVBoxLayout(dll_group)

        compile_dll_btn = QPushButton("Compile Adobe Injector as DLL")
        compile_dll_btn.clicked.connect(self.compile_as_dll)
        compile_dll_btn.setToolTip("Compile AutoIt3 script as DLL for ctypes integration")

        dll_layout.addWidget(compile_dll_btn)
        dll_layout.addWidget(QLabel("Status: Not compiled"))

        layout.addWidget(dll_group)

        com_group = QGroupBox("AutoIt3X COM Interface")
        com_layout = QVBoxLayout(com_group)

        register_com_btn = QPushButton("Register AutoIt3X.dll")
        register_com_btn.clicked.connect(self.register_autoit_com)

        test_com_btn = QPushButton("Test COM Interface")
        test_com_btn.clicked.connect(self.test_com_interface)

        com_layout.addWidget(register_com_btn)
        com_layout.addWidget(test_com_btn)

        layout.addWidget(com_group)

        resource_group = QGroupBox("Resource Modification")
        resource_layout = QVBoxLayout(resource_group)

        extract_btn = QPushButton("Extract Resources")
        extract_btn.clicked.connect(self.extract_resources)

        modify_btn = QPushButton("Modify & Rebrand")
        modify_btn.clicked.connect(self.modify_resources)

        rebuild_btn = QPushButton("Rebuild Executable")
        rebuild_btn.clicked.connect(self.rebuild_executable)

        resource_layout.addWidget(extract_btn)
        resource_layout.addWidget(modify_btn)
        resource_layout.addWidget(rebuild_btn)

        layout.addWidget(resource_group)

        config_group = QGroupBox("Silent Mode Configuration")
        config_layout = QVBoxLayout(config_group)

        create_config_btn = QPushButton("Create Silent Config")
        create_config_btn.clicked.connect(self.create_silent_config)
        create_config_btn.setToolTip("Create configuration for fully automated patching")

        config_layout.addWidget(create_config_btn)

        layout.addWidget(config_group)
        layout.addStretch()

        return tab

    def launch_subprocess(self, hidden: bool = False) -> None:
        """Launch Adobe Injector as subprocess with control.

        Args:
            hidden: Whether to launch the process in hidden mode.

        Raises:
            ValueError: If the command contains unsafe characters or Adobe Injector executable not found.

        """
        if self.subprocess_output is None or self.cmd_args is None:
            return

        adobe_injector_path = get_project_root() / "tools/AdobeInjector/AdobeInjector.exe"

        if not adobe_injector_path.exists():
            self.subprocess_output.append(f"ERROR: {adobe_injector_path} not found")
            return

        try:
            cmd = [str(adobe_injector_path)]
            if args := self.cmd_args.text().strip():
                cmd.extend(args.split())

            if hidden:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                    error_msg = f"Unsafe command: {cmd}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                cwd_str = str(adobe_injector_path.parent).replace(";", "").replace("|", "").replace("&", "")
                self.adobe_injector_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    startupinfo=startupinfo,
                    cwd=cwd_str,
                    shell=False,
                )
                self.subprocess_output.append("Adobe Injector launched in hidden mode")

                threading.Thread(target=self.monitor_subprocess, daemon=True).start()

            else:
                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                    error_msg = f"Unsafe command: {cmd}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                cwd_str = str(adobe_injector_path.parent).replace(";", "").replace("|", "").replace("&", "")
                self.adobe_injector_process = subprocess.Popen(cmd, cwd=cwd_str, shell=False)
                self.subprocess_output.append("Adobe Injector launched in visible mode")

        except Exception as e:
            self.subprocess_output.append(f"ERROR: {e}")

    def monitor_subprocess(self) -> None:
        """Monitor subprocess output and display results in the UI.

        Continuously reads output from the Adobe Injector subprocess and
        updates the subprocess output display widget with the process output.
        Handles exceptions gracefully and updates the display on error.

        """
        if not self.adobe_injector_process:
            return

        try:
            stdout = self.adobe_injector_process.stdout
            if stdout is None:
                return

            for line in iter(stdout.readline, b""):
                if line:
                    output_text = line.decode("utf-8", errors="ignore").strip()
                    if self.subprocess_output is not None:
                        self.subprocess_output.append(output_text)

            if self.subprocess_output is not None:
                self.subprocess_output.append("Process terminated")

        except Exception as e:
            if self.subprocess_output is not None:
                self.subprocess_output.append(f"Monitor error: {e}")

    def scan_in_terminal(self) -> None:
        """Run scan operation in terminal.

        Executes the Adobe Injector scan command in the embedded terminal.

        """
        self.execute_in_terminal("AdobeInjector.exe /scan")

    def patch_in_terminal(self) -> None:
        """Run patch operation in terminal.

        Executes the Adobe Injector patch command with silent mode enabled
        in the embedded terminal.

        """
        self.execute_in_terminal("AdobeInjector.exe /patch /silent")

    def custom_terminal_command(self) -> None:
        """Execute custom command in terminal.

        Retrieves the command from the terminal command input field and
        executes it in the embedded terminal.

        """
        if self.terminal_cmd is None:
            return
        if cmd := self.terminal_cmd.text():
            self.execute_in_terminal(cmd)

    def execute_terminal_command(self) -> None:
        """Execute command from input field.

        Wrapper method that delegates to custom_terminal_command to execute
        the command specified in the terminal command input field.

        """
        self.custom_terminal_command()

    def execute_in_terminal(self, command: str) -> None:
        """Execute command in embedded terminal.

        Args:
            command: The command string to execute in the terminal.

        """
        if self.terminal_display is None:
            return

        try:
            terminal_manager = get_terminal_manager()

            if not terminal_manager.is_terminal_available():
                self.terminal_display.append("Terminal not available. Please open Terminal tab first.")
                return

            adobe_injector_dir = get_project_root() / "tools/AdobeInjector"

            command_parts = command.split() if isinstance(command, str) else command
            session_id = terminal_manager.execute_command(
                command_parts,
                capture_output=False,
                auto_switch=True,
                cwd=str(adobe_injector_dir),
            )

            self.terminal_display.append(f"Executed in terminal: {command}")
            self.terminal_display.append(f"Session ID: {session_id}")
            self.injector_started.emit("Command sent to terminal")

        except Exception as e:
            self.terminal_display.append(f"Terminal error: {e}")

    def compile_as_dll(self) -> None:
        """Compile AutoIt3 script as DLL using Aut2exe compiler.

        Searches for Aut2exe compiler in standard locations and compiles
        the AdobeInjector.au3 script to a DLL for ctypes integration.

        """
        if self.subprocess_output is None:
            return

        import shutil

        self.subprocess_output.append("Starting DLL compilation process...")

        adobe_injector_dir = get_project_root() / "tools/AdobeInjector"
        source_script = adobe_injector_dir / "AdobeInjector.au3"
        output_dll = adobe_injector_dir / "AdobeInjector.dll"

        if not source_script.exists():
            if (adobe_injector_dir / "AdobeInjector.exe").exists():
                self.subprocess_output.append("Source .au3 script not found, but compiled .exe exists")
                self.subprocess_output.append("DLL compilation requires original AutoIt3 source code")
                return
            self.subprocess_output.append(f"ERROR: Source script not found: {source_script}")
            return

        aut2exe_paths = [
            r"C:\Program Files (x86)\AutoIt3\Aut2Exe\Aut2exe.exe",
            r"C:\Program Files\AutoIt3\Aut2Exe\Aut2exe.exe",
            r"C:\AutoIt3\Aut2Exe\Aut2exe.exe",
        ]
        aut2exe_path = shutil.which("Aut2exe")
        if aut2exe_path is None:
            for path in aut2exe_paths:
                if pathlib.Path(path).exists():
                    aut2exe_path = path
                    break

        if aut2exe_path is None:
            self.subprocess_output.append("ERROR: AutoIt3 compiler (Aut2exe.exe) not found")
            self.subprocess_output.append("Install AutoIt3 from https://www.autoitscript.com/site/autoit/downloads/")
            self.subprocess_output.append("Or add Aut2exe.exe directory to PATH")
            return

        self.subprocess_output.append(f"Found compiler: {aut2exe_path}")
        self.subprocess_output.append(f"Compiling: {source_script}")

        try:
            compile_cmd = [
                aut2exe_path,
                "/in", str(source_script),
                "/out", str(output_dll),
                "/comp", "4",
                "/nopack",
            ]

            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(adobe_injector_dir),
                check=False,
            )

            if result.returncode == 0 and output_dll.exists():
                dll_size = output_dll.stat().st_size
                self.subprocess_output.append("SUCCESS: DLL compiled successfully")
                self.subprocess_output.append(f"Output: {output_dll}")
                self.subprocess_output.append(f"Size: {dll_size:,} bytes")
            else:
                self.subprocess_output.append(f"Compilation failed with code: {result.returncode}")
                if result.stdout:
                    self.subprocess_output.append(f"stdout: {result.stdout}")
                if result.stderr:
                    self.subprocess_output.append(f"stderr: {result.stderr}")

        except subprocess.TimeoutExpired:
            self.subprocess_output.append("ERROR: Compilation timed out after 120 seconds")
        except Exception as e:
            self.subprocess_output.append(f"ERROR: Compilation failed: {e}")

    def register_autoit_com(self) -> None:
        """Register AutoIt3X.dll for COM usage.

        Executes regsvr32 to register the AutoIt3X.dll library for COM
        interoperability. Displays registration status in the subprocess
        output widget.

        """
        if self.subprocess_output is None:
            return
        try:
            result = subprocess.run(["regsvr32", "/s", "AutoIt3X.dll"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                self.subprocess_output.append("AutoIt3X.dll registered successfully")
            else:
                self.subprocess_output.append(f"Registration failed: {result.stderr}")
        except Exception as e:
            self.subprocess_output.append(f"Error: {e}")

    def test_com_interface(self) -> None:
        """Test AutoIt3X COM interface.

        Attempts to connect to the AutoIt3X COM object and retrieve its
        version. Displays the version information or error message in the
        subprocess output widget.

        """
        if self.subprocess_output is None:
            return
        try:
            import win32com.client

            autoit = win32com.client.Dispatch("AutoItX3.Control")
            version = autoit.Version()
            self.subprocess_output.append(f"AutoIt3X COM Version: {version}")
        except Exception as e:
            self.subprocess_output.append(f"COM test failed: {e}")

    def extract_resources(self) -> None:
        """Extract resources from Adobe Injector executable using pefile.

        Extracts icons, version info, manifests, and other embedded resources
        to the tools/AdobeInjector/resources directory for modification.

        """
        if self.subprocess_output is None:
            return

        self.subprocess_output.append("Starting resource extraction...")

        adobe_injector_dir = get_project_root() / "tools/AdobeInjector"
        exe_path = adobe_injector_dir / "AdobeInjector.exe"
        output_dir = adobe_injector_dir / "resources"

        if not exe_path.exists():
            self.subprocess_output.append(f"ERROR: Executable not found: {exe_path}")
            return

        try:
            import pefile
        except ImportError:
            self.subprocess_output.append("ERROR: pefile library not available")
            self.subprocess_output.append("Install with: pip install pefile")
            return

        output_dir.mkdir(parents=True, exist_ok=True)
        extracted_count = 0

        try:
            pe = pefile.PE(str(exe_path))

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                self.subprocess_output.append(f"Found resource directory in {exe_path.name}")

                resource_type_names = {
                    1: "CURSOR",
                    2: "BITMAP",
                    3: "ICON",
                    4: "MENU",
                    5: "DIALOG",
                    6: "STRING",
                    7: "FONTDIR",
                    8: "FONT",
                    9: "ACCELERATOR",
                    10: "RCDATA",
                    11: "MESSAGETABLE",
                    12: "GROUP_CURSOR",
                    14: "GROUP_ICON",
                    16: "VERSION",
                    24: "MANIFEST",
                }

                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    type_id = resource_type.id if resource_type.id is not None else 0
                    type_name = resource_type_names.get(type_id, f"TYPE_{type_id}")

                    if hasattr(resource_type, "name") and resource_type.name:
                        type_name = str(resource_type.name)

                    type_dir = output_dir / type_name
                    type_dir.mkdir(exist_ok=True)

                    if hasattr(resource_type, "directory"):
                        for resource_id in resource_type.directory.entries:
                            res_id = resource_id.id if resource_id.id is not None else 0
                            res_name = str(resource_id.name) if hasattr(resource_id, "name") and resource_id.name else str(res_id)

                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

                                    ext = ".bin"
                                    if type_id == 3:
                                        ext = ".ico"
                                    elif type_id == 2:
                                        ext = ".bmp"
                                    elif type_id == 24:
                                        ext = ".manifest"
                                    elif type_id == 16:
                                        ext = ".version"

                                    output_file = type_dir / f"{res_name}{ext}"
                                    pathlib.Path(output_file).write_bytes(data)

                                    extracted_count += 1
                                    self.subprocess_output.append(f"  Extracted: {type_name}/{res_name}{ext} ({size} bytes)")

            if hasattr(pe, "VS_VERSIONINFO"):
                version_info = {}
                for fileinfo in pe.FileInfo:
                    for entry in fileinfo:
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    version_info[key.decode("utf-8", errors="ignore")] = value.decode("utf-8", errors="ignore")

                if version_info:
                    import json
                    version_file = output_dir / "version_info.json"
                    with pathlib.Path(version_file).open("w", encoding="utf-8") as f:
                        json.dump(version_info, f, indent=2)
                    self.subprocess_output.append("  Extracted version info to version_info.json")
                    extracted_count += 1

            pe.close()

            self.subprocess_output.append(f"SUCCESS: Extracted {extracted_count} resources to {output_dir}")

        except Exception as e:
            self.subprocess_output.append(f"ERROR: Resource extraction failed: {e}")

    def modify_resources(self) -> None:
        """Modify and rebrand resources."""
        if self.subprocess_output is None:
            return
        rebrand: dict[str, str] = {
            "ProductName": "Adobe Injector",
            "CompanyName": "Intellicrack",
            "FileDescription": "Adobe License Bypass Module",
            "InternalName": "AdobeInjector",
            "LegalCopyright": "Intellicrack 2025",
            "OriginalFilename": "adobe_injector.exe",
        }

        config_path = get_project_root() / "tools/AdobeInjector/rebrand.json"
        with pathlib.Path(config_path).open("w", encoding="utf-8") as f:
            json.dump(rebrand, f, indent=2)

        self.subprocess_output.append(f"Rebranding configuration saved to {config_path}")

    def rebuild_executable(self) -> None:
        """Rebuild executable with modified resources using LIEF or pefile.

        Recompiles the AdobeInjector executable with modified resources from
        the resources directory, applying version info and icon changes.

        """
        if self.subprocess_output is None:
            return

        self.subprocess_output.append("Starting executable rebuild...")

        adobe_injector_dir = get_project_root() / "tools/AdobeInjector"
        exe_path = adobe_injector_dir / "AdobeInjector.exe"
        resources_dir = adobe_injector_dir / "resources"
        rebrand_config = adobe_injector_dir / "rebrand.json"
        output_path = adobe_injector_dir / "AdobeInjector_modified.exe"
        backup_path = adobe_injector_dir / "AdobeInjector_original.exe"

        if not exe_path.exists():
            self.subprocess_output.append(f"ERROR: Executable not found: {exe_path}")
            return

        if not resources_dir.exists():
            self.subprocess_output.append("WARNING: Resources directory not found")
            self.subprocess_output.append("Run 'Extract Resources' first to extract resources for modification")

        try:
            import lief
            use_lief = True
        except ImportError:
            use_lief = False
            self.subprocess_output.append("INFO: LIEF not available, trying pefile")

        if use_lief:
            try:
                import shutil

                if not backup_path.exists():
                    shutil.copy2(exe_path, backup_path)
                    self.subprocess_output.append(f"Created backup: {backup_path}")

                binary = lief.parse(str(exe_path))
                if binary is None:
                    self.subprocess_output.append("ERROR: Failed to parse executable with LIEF")
                    return

                modified = False

                if rebrand_config.exists():
                    with pathlib.Path(rebrand_config).open("r", encoding="utf-8") as f:
                        rebrand_data = json.load(f)
                    self.subprocess_output.append("Applying rebrand configuration...")

                    if hasattr(binary, "resources_manager"):
                        res_manager = binary.resources_manager
                        if hasattr(res_manager, "version") and res_manager.version is not None:
                            version = res_manager.version
                            string_table = version.string_file_info.langcode_items[0] if version.string_file_info.langcode_items else None
                            if string_table:
                                for key, value in rebrand_data.items():
                                    if hasattr(string_table, key.lower()):
                                        setattr(string_table, key.lower(), value)
                                        self.subprocess_output.append(f"  Updated {key}: {value}")
                                        modified = True

                if resources_dir.exists():
                    icon_dir = resources_dir / "ICON"
                    if icon_dir.exists():
                        icon_files = list(icon_dir.glob("*.ico"))
                        if icon_files:
                            self.subprocess_output.append(f"Found {len(icon_files)} icon files for replacement")

                if modified:
                    binary.write(str(output_path))
                    output_size = output_path.stat().st_size
                    self.subprocess_output.append(f"SUCCESS: Modified executable saved to {output_path}")
                    self.subprocess_output.append(f"Size: {output_size:,} bytes")
                else:
                    self.subprocess_output.append("No modifications applied - check rebrand.json configuration")

            except Exception as e:
                self.subprocess_output.append(f"ERROR: LIEF rebuild failed: {e}")
                use_lief = False

        if not use_lief:
            try:
                import shutil

                import pefile

                if not backup_path.exists():
                    shutil.copy2(exe_path, backup_path)
                    self.subprocess_output.append(f"Created backup: {backup_path}")

                shutil.copy2(exe_path, output_path)

                pe = pefile.PE(str(output_path))

                if rebrand_config.exists():
                    with pathlib.Path(rebrand_config).open("r", encoding="utf-8") as f:
                        rebrand_data = json.load(f)
                    self.subprocess_output.append("Rebrand config loaded - pefile modification limited")
                    self.subprocess_output.append("For full resource modification, install LIEF: pip install lief")

                pe.write(str(output_path))
                pe.close()

                output_size = output_path.stat().st_size
                self.subprocess_output.append(f"SUCCESS: Created modified executable: {output_path}")
                self.subprocess_output.append(f"Size: {output_size:,} bytes")
                self.subprocess_output.append("NOTE: For full resource editing, install LIEF library")

            except ImportError:
                self.subprocess_output.append("ERROR: Neither LIEF nor pefile available")
                self.subprocess_output.append("Install with: pip install lief pefile")
            except Exception as e:
                self.subprocess_output.append(f"ERROR: pefile rebuild failed: {e}")

    def create_silent_config(self) -> None:
        """Create configuration for silent/automated operation."""
        if self.subprocess_output is None:
            return
        config: dict[str, bool | str] = {
            "auto_scan": True,
            "auto_patch": True,
            "target_path": "C:\\Program Files\\Adobe",
            "backup_files": True,
            "block_hosts": True,
            "create_firewall_rules": True,
            "remove_ags": True,
            "silent_mode": True,
        }

        config_path = get_project_root() / "tools/AdobeInjector/silent_config.json"
        with pathlib.Path(config_path).open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        self.subprocess_output.append(f"Silent configuration created: {config_path}")

    def on_method_changed(self, method: str) -> None:
        """Handle integration method change.

        Args:
            method: The selected integration method name.

        """
        if self.method_tabs is None:
            return

        method_map: dict[str, int] = {
            "Embedded Window (Native)": 0,
            "Subprocess Control": 1,
            "Terminal Execution": 2,
            "DLL Injection": 3,
            "AutoIt3X COM": 3,
        }

        if method in method_map:
            self.method_tabs.setCurrentIndex(method_map[method])

    def on_status_update(self, status: str) -> None:
        """Handle status updates from integration.

        Args:
            status: The status message from the integration.

        """
        if self.subprocess_output is not None:
            self.subprocess_output.append(status)
        self.injector_started.emit(status)
