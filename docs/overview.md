# Intellicrack Documentation

Welcome to the official documentation for **Intellicrack** - a comprehensive binary analysis and security research tool with GUI, AI integration, and advanced analysis capabilities.

## 🚀 Quick Start

1. **Installation**: Run `dependencies\install_dependencies.bat` to install all required dependencies
2. **Launch**: Execute `RUN_INTELLICRACK.bat` to start the application
3. **First Analysis**: Open a binary file and click "Analyze" to begin

## 📖 Documentation Overview

### Usage Guides
- [**AI Assistant**](usage/ai_assistant.md) - Comprehensive guide to AI-powered features, model selection, and provider configuration
- [**Basic Analysis**](usage/basic_analysis.md) - Learn how to analyze binaries, identify vulnerabilities, and understand protection mechanisms
- [**Patching**](usage/patching.md) - Guide to patching binaries, bypassing protections, and creating modified executables
- [**CLI Usage**](usage/cli_usage.md) - Command-line interface documentation
- [**API Model Import**](usage/api_model_import.md) - Documentation for importing and using AI models

### Integration Guides
- [**Frida Integration**](guides/FRIDA_INTEGRATION_GUIDE.md) - Dynamic instrumentation with Frida
- [**Radare2 Integration**](guides/RADARE2_INTEGRATION_GUIDE.md) - Using Radare2 for analysis
- [**QEMU Setup**](guides/QEMU_SETUP_GUIDE.md) - Emulation and dynamic analysis

### Development
- [**Plugin Development**](development/plugins.md) - Create custom plugins to extend Intellicrack's functionality
- [**Architecture Overview**](architecture/overview.md) - System design and architecture

## 🎯 Key Features

### Core Capabilities
- **Multi-Format Support**: PE, ELF, Mach-O binary analysis
- **Protection Detection**: Anti-debug, packing, obfuscation identification
- **Vulnerability Scanning**: Buffer overflows, format strings, integer overflows
- **License Bypass**: Various bypass mechanisms for software protections
- **Network Analysis**: Traffic capture, protocol fingerprinting, SSL interception

### Advanced Features
- **AI Integration**: ML-powered pattern recognition and vulnerability prediction
- **Distributed Processing**: Ray, Dask, and multiprocessing support
- **GPU Acceleration**: CUDA/OpenCL acceleration for intensive operations
- **Symbolic Execution**: Advanced path exploration and constraint solving
- **Dynamic Analysis**: Runtime behavior analysis and instrumentation

### User Interface
- **Tabbed Interface**: Organized workspace for different analysis tasks
- **Hex Editor**: Built-in hex viewer/editor with pattern highlighting
- **Visual Patch Editor**: Graphical interface for binary modifications
- **Real-time Logs**: Live logging and debugging information
- **Plugin Manager**: Easy plugin installation and management

## 🛠️ System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Python**: 3.8 or higher
- **RAM**: 8GB minimum (16GB recommended)
- **Disk**: 2GB free space
- **CPU**: 4 cores minimum

### Optional Requirements
- **GPU**: NVIDIA, AMD, or Intel GPU with appropriate drivers for acceleration
- **Ghidra**: For advanced decompilation features
- **radare2**: For additional analysis capabilities

## 🔧 Configuration

Intellicrack uses a JSON configuration file that includes:
- Analysis engine settings
- Network configuration
- AI model paths
- Plugin directories
- Logging preferences

See the [Configuration Guide](usage/basic_analysis.md#configuration) for details.

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**: Run `dependencies\install_dependencies.bat` to ensure all packages are installed
2. **GPU Not Detected**: Normal in WSL/VMs - CPU fallback will be used automatically
3. **Qt Warnings**: Set environment variables in launch script to suppress
4. **Slow Analysis**: Enable GPU acceleration or distributed processing

### Getting Help

- Review error messages in the Logs tab
- Enable debug logging for detailed diagnostics
- Check the troubleshooting section in this documentation

## 📚 Additional Resources

### Tutorials
- [Analyzing a Windows Executable](usage/basic_analysis.md#windows-executable)
- [Creating a License Bypass](usage/patching.md#license-bypass)
- [Writing Your First Plugin](development/plugins.md#first-plugin)

### Reference
- [API Documentation](reference/api_reference.md)
- [Plugin API](development/plugins.md#api-reference)
- [Network Protocols](reference/network_protocols.md)
- [Project Structure](reference/PROJECT_STRUCTURE.md)

## 📄 License

Intellicrack is released under the GNU General Public License v3.0. See LICENSE file for details.
