# Intellicrack

A comprehensive binary analysis and security research platform designed to help software developers identify and strengthen vulnerabilities in their own licensing and protection systems.

![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-GPL%20v3-green)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey)

## Features

### Core Capabilities
- **Multi-Format Binary Analysis**: PE, ELF, Mach-O support
- **Protection Detection**: Anti-debug, packing, obfuscation identification
- **Vulnerability Research**: Buffer overflows, format strings, integer overflows
- **Exploitation Framework**: Advanced exploit development and testing
- **Network Analysis**: Traffic capture, protocol fingerprinting, license server emulation

### Advanced Features
- **AI/ML Integration**: Multiple AI providers with dynamic model fetching (OpenAI, Anthropic, Google, Local models)
- **Template-Free Design**: No hardcoded templates or rigid patterns - AI generates adaptive, context-aware code and responses
- **GPU Acceleration**: NVIDIA, AMD, and Intel GPU support for intensive operations
- **Parallel Processing**: Multi-core processing support via Python multiprocessing
- **Symbolic Execution**: Advanced path exploration and constraint solving
- **Dynamic Analysis**: Runtime behavior analysis and instrumentation
- **C2 Infrastructure**: Command and control capabilities for security testing

### User Interface
- **Modern GUI**: Built with PyQt6 for Windows 11 compatibility
- **Three-Panel Layout**: Professional IDE-like interface with tabs and output panel
- **Hex Editor**: Built-in viewer/editor with pattern highlighting and data inspection
- **AI Assistant Tab**: Integrated AI-powered analysis and script generation
- **Embedded Terminal**: Full-featured terminal emulator with multi-session support and PTY integration
- **Plugin System**: Extensible architecture for custom tools
- **Real-time Logging**: Comprehensive logging with adjustable verbosity

## Requirements

### System Requirements
- **OS**: Windows 11
- **Python**: 3.12+ (required for full functionality)
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 5GB free space (for all tools and dependencies)
- **CPU**: 4 cores minimum

### Optional Requirements
- **GPU**: NVIDIA, AMD, or Intel GPU with appropriate drivers
- **Ghidra**: For advanced decompilation
- **radare2**: For additional analysis capabilities

## Installation

### Prerequisites

**1. Install Pixi package manager:**

```bash
# Windows (PowerShell)
iwr -useb https://pixi.sh/install.ps1 | iex

# Or via winget
winget install prefix-dev.pixi
```

**2. Install `just` command runner:**

```bash
# Windows (via winget)
winget install --id Casey.Just -e

# Or via scoop
scoop install just

# Or via cargo (after running 'just install')
pixi run cargo install just
```

**Note:** Rust, Node.js, radare2, and git are automatically installed by pixi. Rustup and JDK 21 are installed via winget during `just install`.

### Automated Installation (Recommended)

1. **Clone the repository**

   ```bash
   git clone https://github.com/Zachanardo/Intellicrack.git
   cd Intellicrack
   ```

2. **Run automated setup**

   ```bash
   # Installs all dependencies + Intel XPU + linters + Rust build
   just install
   ```

   This automatically runs:
   - `pixi install` - Installs all Python/Conda dependencies
   - `rustup update stable` - Updates Rust toolchain to latest
   - JDK 21 installation (system-wide via winget)
   - Latest Ghidra download and installation to `tools/ghidra/`
   - Latest radare2 download and installation to `tools/radare2/`
   - Latest QEMU download and installation to `tools/qemu/`
   - Intel XPU PyTorch installation (for Intel GPU acceleration)
   - ESLint + Markdownlint installation
   - Rust launcher build (release mode)

### Manual Installation

If you prefer step-by-step installation:

1. **Install base dependencies**

   ```bash
   pixi install
   ```

2. **Run post-install setup**

   ```bash
   pixi run setup
   ```

### Activate Environment

```bash
# Activate pixi shell
pixi shell

# Or run commands directly
pixi run intellicrack --help
pixi run intellicrack-gui
```

### Dependencies

Intellicrack automatically manages dependencies for Windows 11:

#### Windows 11 Features
- **Primary Engine**: angr (full Windows 11 support)
- **GPU Support**: Intel Arc B580 detection with GIL crash prevention
- All Windows 11 users get a fully functional system

#### Symbolic Execution Support
- **angr**: Windows 11 optimized, installed by default, recommended for all users
- **Built-in fallback**: For minimal functionality

## 🎯 Usage

### GUI Mode

Launch the graphical interface:

```bash
# Using the launcher script
python launch_intellicrack.py

# Using module mode
python -m intellicrack --gui
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
from intellicrack.core.analysis import BinaryAnalyzer

analyzer = BinaryAnalyzer()
result = analyzer.analyze_binary("target.exe", {
    "deep_scan": True,
    "detect_protections": True
})

print(f"File type: {result.file_format}")
print(f"Protections: {result.protections}")
```

## Terminal Tab & Activation Tools

Intellicrack features an embedded terminal emulator for interactive process execution and activation workflows.

### Features
- **Full PTY Support**: Windows ConPTY integration for native terminal experience
- **Multi-Session Management**: Create and manage multiple terminal sessions simultaneously
- **ANSI Color Support**: Full color and formatting support for terminal output
- **Smart Auto-Navigation**: Interactive processes automatically switch to Terminal tab
- **Process Control**: Start, stop, and monitor processes with real-time feedback
- **Copy/Paste**: Full clipboard integration with right-click context menu
- **Scrollback Buffer**: Configurable buffer (10,000 lines default) with export functionality

### Windows & Adobe Activation

The integrated Activation Tools provide streamlined access to licensing analysis capabilities:

**Windows Activation**:
- Interactive menu-driven activation via embedded terminal
- Real-time activation status checking
- Multiple activation method support (HWID, KMS38, Online KMS)
- No external console windows - all operations within Intellicrack GUI

**Adobe Product Activation**:
- Frida-based injection for Adobe licensing analysis
- Interactive terminal-based workflow
- Live process monitoring and feedback

### Usage

1. **Access Activation Tools**:
   - Navigate to **Tools** tab → **Activation Tools** sub-tab
   - Click "Check Windows Activation Status" for current status
   - Click "Activate Windows (Interactive)" to launch activation workflow

2. **Interactive Terminal**:
   - Automatically switches to **Terminal** tab when activation starts
   - Full menu interaction with keyboard input
   - Real-time process output with color formatting
   - Use Ctrl+C to interrupt, right-click for copy/paste

3. **Manual Terminal Usage**:
   - Navigate to **Terminal** tab (7th tab, between Tools and Settings)
   - Click "+" to create new terminal session
   - Execute custom commands and scripts interactively

For detailed terminal usage instructions, see the [Terminal Tab User Guide](docs/TERMINAL_TAB_USER_GUIDE.md).

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- [Architecture Overview](docs/architecture/COMPREHENSIVE_ARCHITECTURE.md)
- [User Guide](docs/guides/COMPREHENSIVE_USER_GUIDE.md)
- [Terminal Tab User Guide](docs/TERMINAL_TAB_USER_GUIDE.md)
- [Terminal Widget API Documentation](docs/TERMINAL_WIDGET_API.md)
- [Terminal Migration Guide](docs/TERMINAL_MIGRATION_GUIDE.md)
- [AI Assistant Guide](docs/usage/ai_assistant.md)
- [AI Models Quick Reference](docs/reference/AI_MODELS_QUICK_REFERENCE.md)
- [Plugin Development](docs/development/plugins.md)
- [GPU Acceleration Guide](docs/guides/GPU_ACCELERATION_GUIDE.md)
- [Security and Ethics](docs/security/SECURITY_AND_ETHICS_GUIDE.md)

## Configuration

Intellicrack uses JSON configuration files. Key settings include:

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

See the [Configuration Reference](docs/reference/CONFIGURATION_REFERENCE.md) for details.

## Plugins

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

## Examples

### Basic Binary Analysis

```python
from intellicrack.core.analysis import BinaryAnalyzer

# Analyze executable
analyzer = BinaryAnalyzer()
result = analyzer.analyze_binary("protected.exe")
print(f"SHA256: {result.hashes['sha256']}")
print(f"Entropy: {result.entropy}")
```

### Protection Detection

```python
from intellicrack.protection import ProtectionDetector

detector = ProtectionDetector()
protections = detector.detect("app.exe")

for protection in protections:
    print(f"{protection.type}: {protection.description}")
```

### Network Analysis

```python
from intellicrack.core.network import NetworkTrafficAnalyzer

analyzer = NetworkTrafficAnalyzer()
analyzer.start_capture()
# ... run target application ...
packets = analyzer.stop_capture()
```

## Troubleshooting

### Common Issues

1. **Import Errors**

```text
   Solution: Ensure all dependencies are installed from requirements.lock
```

1. **GPU Not Detected**

```text
   Normal in WSL/VMs - CPU fallback will be used automatically
```

1. **Qt Warnings**

```text
   PyQt6 warnings can be ignored - application functions normally
```

1. **Intel Arc Graphics Issues**

```text
   Intel Arc B580 GPU issues are automatically detected and handled
   GIL crash prevention is built-in
```

1. **Slow Analysis**

```text
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

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style guidelines
- Development setup
- Pull request process
- Bug reporting

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**Intellicrack** is developed for **defensive security research** to help software developers:

- **Identify weaknesses** in their own licensing protection mechanisms
- **Test robustness** of their protection implementations in controlled environments
- **Strengthen defenses** against potential attacks by understanding attack vectors
- **Validate security** of their own software before deployment

This tool is for educational and authorized security research purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.
