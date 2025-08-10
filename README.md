# Intellicrack

A comprehensive binary analysis and security research tool with GUI, AI integration, and advanced analysis capabilities.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-GPL%20v3-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## 🚀 Features

### Core Capabilities
- **Multi-Format Binary Analysis**: PE, ELF, Mach-O support
- **Protection Detection**: Anti-debug, packing, obfuscation identification
- **Vulnerability Scanning**: Buffer overflows, format strings, integer overflows
- **License Bypass Mechanisms**: Various bypass techniques for software protections
- **Network Analysis**: Traffic capture, protocol fingerprinting, SSL interception

### Advanced Features
- **AI/ML Integration**: 16+ AI providers with dynamic model fetching (OpenAI, Anthropic, Google, Local models, and more)
- **GPU Acceleration**: NVIDIA, AMD, and Intel GPU support for intensive operations
- **Distributed Processing**: Ray, Dask, and multiprocessing support
- **Symbolic Execution**: Advanced path exploration and constraint solving
- **Dynamic Analysis**: Runtime behavior analysis and instrumentation

### User Interface
- **Modern GUI**: Built with PyQt5 for cross-platform compatibility
- **Hex Editor**: Built-in viewer/editor with pattern highlighting
- **Visual Patch Editor**: Graphical interface for binary modifications
- **Plugin System**: Extensible architecture for custom tools
- **Real-time Logging**: Comprehensive logging with adjustable verbosity

## 📋 Requirements

### System Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Python**: 3.11 or 3.12 (required for full functionality)
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 5GB free space (for all tools and dependencies)
- **CPU**: 4 cores minimum

### Optional Requirements
- **GPU**: NVIDIA, AMD, or Intel GPU with appropriate drivers
- **Ghidra**: For advanced decompilation
- **radare2**: For additional analysis capabilities

## 🔧 Installation

### Automatic Installation (Recommended)

Just run the PowerShell installer:

```powershell
# Windows (PowerShell)
.\Install.ps1
```

This single script automatically:
- ✅ Installs Python 3.11 if not present
- ✅ Detects your GPU (NVIDIA/AMD/Intel) and configures accordingly
- ✅ Installs all 100+ Python packages
- ✅ Installs system tools (Ghidra, Radare2, x64dbg, etc.)
- ✅ Sets up the complete environment
- ✅ Creates desktop shortcuts

**No manual configuration needed!**

### Manual Installation

If you prefer manual setup:

```bash
# 1. Install Python 3.11 or 3.12 (3.13+ not supported)

# 2. Clone the repository
git clone https://github.com/yourusername/intellicrack.git
cd intellicrack

# 3. Install dependencies
pip install -r requirements/requirements.txt

# 4. Launch the application
python launch_intellicrack.py
```

### Platform-Specific Dependencies

Intellicrack automatically manages platform-specific dependencies:

#### Windows
- **Primary Engine**: angr (full Windows support)
- **Excluded**: manticore (Linux-only, not required)
- All Windows users get a fully functional system without Linux-specific tools

#### Linux/Unix
- **Primary Engine**: angr (recommended)
- **Secondary Engine**: manticore (automatically installed)
- **Optional**: Install with `pip install intellicrack[linux]` for all Linux tools

#### Symbolic Execution Support
- **angr**: Cross-platform, installed by default, recommended for all users
- **manticore**: Linux-only, optional fallback
- **simconcolic**: Built-in fallback for minimal functionality

## 🎯 Usage

### GUI Mode
Simply run the launcher to start the graphical interface:
```bash
python launch_intellicrack.py
```

### Command Line
```bash
# Analyze a binary
python -m intellicrack analyze target.exe

# Quick vulnerability scan
python -m intellicrack scan --vulns target.exe

# Extract strings
python -m intellicrack strings target.exe
```

### Python API
```python
from intellicrack.core.analysis import CoreAnalyzer

analyzer = CoreAnalyzer()
result = analyzer.analyze_binary("target.exe", {
    "deep_scan": True,
    "detect_protections": True
})

print(f"File type: {result['file_info']['type']}")
print(f"Protections: {result['protections']}")
```

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Getting Started](docs/index.md)
- [AI Assistant Guide](docs/usage/ai_assistant.md) - **NEW**: Dynamic model selection with 16+ providers
- [AI Models Quick Reference](docs/AI_MODELS_QUICK_REFERENCE.md) - Provider setup and model recommendations
- [Basic Analysis Guide](docs/usage/basic_analysis.md)
- [Patching Guide](docs/usage/patching.md)
- [Plugin Development](docs/development/plugins.md)
- [API Reference](docs/api_reference.md)
- [Network Protocol Analysis](docs/network_protocols.md)

## 🛠️ Configuration

Intellicrack uses a JSON configuration file. Key settings include:

```json
{
    "analysis": {
        "timeout": 300,
        "parallel_threads": 8,
        "enable_gpu": true
    },
    "logging": {
        "level": "INFO",
        "enable_comprehensive_logging": true
    }
}
```

See [Configuration Guide](docs/usage/basic_analysis.md#configuration) for details.

## 🧩 Plugins

Extend functionality with custom plugins:

```python
from intellicrack.plugins import PluginBase

class MyPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"

    def run(self, binary_data, **kwargs):
        # Your analysis logic here
        return results
```

See the [Plugin Development Guide](docs/development/plugins.md) for more information.

## 🔍 Examples

### Basic Binary Analysis
```python
from intellicrack.utils.binary_analysis import analyze_binary

# Analyze executable
result = analyze_binary("protected.exe")
print(f"SHA256: {result['hashes']['sha256']}")
print(f"Entropy: {result['entropy']}")
```

### Vulnerability Detection
```python
from intellicrack.core.analysis import VulnerabilityEngine

engine = VulnerabilityEngine()
vulnerabilities = engine.scan_binary("app.exe")

for vuln in vulnerabilities:
    print(f"{vuln.type}: {vuln.description}")
```

### Network Analysis
```python
from intellicrack.core.network import NetworkTrafficAnalyzer

analyzer = NetworkTrafficAnalyzer()
analyzer.start_capture()
# ... run target application ...
packets = analyzer.stop_capture()
```

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**
   ```
   Solution: Run install_dependencies.bat or pip install -r requirements/requirements.txt
   ```

2. **GPU Not Detected**
   ```
   Normal in WSL/VMs - CPU fallback will be used automatically
   ```

3. **Qt Warnings**
   ```
   Already suppressed in launch script, can be ignored
   ```

4. **Intel Arc Graphics Crash**
   ```
   If application crashes with Intel Arc Graphics:
   - Run RUN_INTELLICRACK_SAFE_MODE.bat for software rendering
   - Or press Y when prompted after crash to restart in safe mode
   - Update Intel Arc drivers to latest version
   ```

5. **Slow Analysis**
   ```
   Enable GPU acceleration or increase parallel_threads in config
   ```

### Debug Mode
Enable detailed logging for troubleshooting:
```json
{
    "logging": {
        "level": "DEBUG",
        "enable_comprehensive_logging": true
    }
}
```

## 🔧 Troubleshooting

### Missing Dependencies

If you encounter errors about missing dependencies:

1. **Flask/llama-cpp-python not available**:
   ```bash
   # Windows
   python fix_missing_core_dependencies.py
   # or
   .\install_missing_dependencies.bat

   # Linux/WSL
   ./install_missing_dependencies.sh
   ```

2. **QEMU not found**:
   - **Windows**: Download from https://www.qemu.org/download/#windows
   - **Linux/WSL**: `sudo apt-get install qemu-system-x86 qemu-user qemu-utils`

3. **Matplotlib 3D projection error**:
   ```bash
   pip uninstall -y matplotlib
   pip install matplotlib==3.8.0
   ```

4. **Intel GPU not detected**:
   - Install Intel Graphics Driver
   - Install Intel Extension for PyTorch: `pip install intel-extension-for-pytorch`

For more detailed troubleshooting, see [Troubleshooting Guide](docs/troubleshooting.md).

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style guidelines
- Development setup
- Pull request process
- Bug reporting

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security research purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.
