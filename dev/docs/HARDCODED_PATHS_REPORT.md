# Hardcoded Paths Report - Intellicrack Project

## Summary
This report contains all hardcoded paths found in the Intellicrack codebase, organized by category and file location.

## 1. Windows System Paths

### Program Files Paths
- **dependencies/fix_tool_paths.py**:
  - Line 51: `r"C:\Program Files\Ghidra\ghidraRun.bat"`
  - Line 127: `r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"`
  - Line 128: `r"C:\Program Files\Docker\Docker\Docker Desktop.exe"`
  - Line 150: `r"C:\Program Files\Git\bin\git.exe"`
  - Line 151: `r"C:\Program Files (x86)\Git\bin\git.exe"`
  - Line 181: `r"C:\Program Files\qemu\qemu-system-x86_64.exe"`
  - Line 198: `r"C:\Program Files\Wireshark\Wireshark.exe"`
  - Line 199: `r"C:\Program Files (x86)\Wireshark\Wireshark.exe"`
  - Line 209: `r"C:\Program Files\Wireshark\tshark.exe"`
  - Line 210: `r"C:\Program Files (x86)\Wireshark\tshark.exe"`
  - Line 239: `r"C:\Program Files\Python311\python.exe"`
  - Line 240: `r"C:\Program Files (x86)\Python311\python.exe"`
  - Line 341: `r"C:\\ProgramData\\chocolatey\\lib\\ghidra\\tools"`

- **dependencies/Install.ps1**:
  - Line 253: `"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"`
  - Line 278: `"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8"`
  - Line 279: `"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8\bin"`
  - Line 476: `"C:\Program Files\Python311\python.exe"`
  - Line 929: `"C:\Program Files\Wireshark"`
  - Line 1006: `"C:\Program Files\Wireshark"`
  - Line 1077: `"C:\Program Files\Wireshark\tshark.exe"`

- **dependencies/Install_Ghidra_Decompiler.bat**:
  - Line 21: `"C:\Program Files\Ghidra\ghidraRun.bat" "C:\ghidra\ghidraRun.bat" "C:\Tools\ghidra\ghidraRun.bat"`
  - Line 48: `C:\Program Files\Ghidra\`

- **dependencies/Install_System_Tools.bat**:
  - Lines 336, 488, 559, 663, 888-893, 907-911, 1043-1044: Various Program Files paths for tools

### Windows System Paths
- **intellicrack/core/protection_bypass/vm_bypass.py**:
  - Line 464: `"C:\\windows\\System32\\drivers\\VBoxGuest.sys"`
  - Line 465: `"C:\\windows\\System32\\drivers\\vmhgfs.sys"`

- **intellicrack/ui/main_app.py**:
  - Line 7763: `fr"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"`

- **intellicrack/utils/dependencies.py**:
  - Line 49: `"C:\\GTK\\bin"`
  - Line 50: `"C:\\Program Files\\GTK3-Runtime Win64\\bin"`

- **intellicrack/utils/process_utils.py**:
  - Lines 110-113: Windows system directories using SystemRoot

- **intellicrack/utils/protection_detection.py**:
  - Line 80: `"C:\\Windows\\System32\\drivers\\vboxguest.sys"`
  - Line 81: `"C:\\Windows\\System32\\drivers\\vmhgfs.sys"`

- **intellicrack/utils/tool_wrappers.py**:
  - Line 939: `"C:\\ghidra\\support\\analyzeHeadless.bat"`
  - Line 940: `"C:\\Program Files\\ghidra\\support\\analyzeHeadless.bat"`

### Tool-Specific Windows Paths
- **intellicrack/config.py**:
  - Line 21: `"ghidra_path": r"C:\Program Files\Ghidra\ghidraRun.bat"`

- **intellicrack/ai/ai_assistant_enhanced.py**:
  - Line 111: Example path `'C:/Program Files/MyApp'`
  - Line 136: Example path `'C:/Program Files/MyApp/app.exe'`

## 2. Unix/Linux Paths

### System Paths
- **examples/sample_binary_analysis.py**:
  - Line 303: `/usr/bin/python3`

- **intellicrack/config.py**:
  - Line 22: `/usr/bin/r2` (for radare2 on Linux)

- **intellicrack/ui/main_app.py**:
  - Line 5258: `/usr/local/ghidra`
  - Line 5260: `/usr/local/bin/frida`

- **intellicrack/utils/additional_runners.py**:
  - Lines 1110-1112: `~/ghidra`, `/opt/ghidra`, `/usr/local/ghidra`

- **intellicrack/utils/exploitation.py**:
  - Line 86: `~/.{target}/trial.dat`

- **intellicrack/utils/tool_wrappers.py**:
  - Line 937: `/opt/ghidra/support/analyzeHeadless`
  - Line 938: `/usr/local/ghidra/support/analyzeHeadless`

### Shebang Lines
Multiple files with:
- `#!/usr/bin/env python3`
- `#!/usr/bin/python3`

## 3. Network Addresses and URLs

### Localhost/Loopback
- **intellicrack/ai/llm_backends.py**:
  - Line 375: `"http://localhost:11434"` (Ollama default)
  - Line 599: `"http://localhost:11434"`

- **intellicrack/core/network/license_server_emulator.py**:
  - Line 491: `ipaddress.IPv4Address("127.0.0.1")`

- **intellicrack/core/network/ssl_interceptor.py**:
  - Line 49: `'listen_ip': '127.0.0.1'`

- **intellicrack/ui/dialogs/llm_config_dialog.py**:
  - Line 406: `"http://localhost:11434"`

- **intellicrack/ui/main_app.py**:
  - Line 13554: `"[INFO] Received connection from 127.0.0.1:45678"`

- **models/repositories/lmstudio_repository.py**:
  - Line 24: `"http://localhost:1234/v1"`

### File URLs
- **intellicrack/core/analysis/rop_generator.py**:
  - Line 664: `f"file://{os.path.abspath(report_path)}"`

- **intellicrack/core/analysis/taint_analyzer.py**:
  - Line 488: `f"file://{os.path.abspath(report_path)}"`

- **intellicrack/ui/main_app.py**:
  - Lines 13698, 13716: `f"file://{report_path}"`

## 4. Configuration File Defaults

### Log and Data Directories
- **intellicrack/config.py** (DEFAULT_CONFIG):
  - Line 20: `os.path.join(os.path.expanduser("~"), "intellicrack", "logs")`
  - Line 24: `os.path.join(os.path.expanduser("~"), "intellicrack", "output")`
  - Line 25: `os.path.join(os.path.expanduser("~"), "intellicrack", "temp")`
  - Line 26: `"plugin_directory": "plugins"`
  - Line 27: `"download_directory": "models/downloads"`

## 5. Relative Paths

### Tool Paths
- **intellicrack/config.py**:
  - Line 22: Relative path for radare2 on Windows: `"..", "..", "radare2", "radare2-5.9.8-w64", "bin", "radare2.exe"`

### Model/Data Paths
- Various references to:
  - `"plugins"`
  - `"models/downloads"`
  - `"models/repositories"`

## Recommendations

1. **Centralize Path Configuration**: All hardcoded paths should be moved to the config system
2. **Use Path Discovery**: Implement dynamic path discovery for tools instead of hardcoding
3. **Platform-Specific Defaults**: Use platform detection to set appropriate defaults
4. **Environment Variables**: Support environment variables for tool paths
5. **User Configuration**: Allow users to configure all tool paths through the UI

## Priority Fixes

### High Priority (Breaking Issues)
1. Ghidra paths - hardcoded in multiple places
2. Python executable paths - assumes Python 3.11
3. CUDA paths - assumes specific version
4. Tool paths in dependencies scripts

### Medium Priority (Functionality Issues)
1. Windows system paths for drivers
2. Unix system paths for tools
3. Default directories in config

### Low Priority (Examples/Documentation)
1. Example paths in AI assistant
2. Shebang lines (generally handled by system)
3. localhost URLs (standard defaults)