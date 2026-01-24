# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PyQt6 GUI Framework**: Complete migration from PyQt5 to PyQt6
  - Modern Qt6 widgets and components
  - Updated orientation constants (Qt.Orientation.Horizontal/Vertical)
  - Enhanced cross-platform compatibility
- **Intel Arc B580 GPU Support**:
  - Automatic detection of Intel Arc B580 graphics cards
  - GIL crash prevention via UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS detection
  - PyTorch import safety mechanisms to prevent system hangs
  - Graceful fallback to CPU when Intel Arc issues detected
- **Enhanced GUI Initialization**:
  - Fixed QMainWindow inheritance and initialization
  - Proper widget creation and layout management
  - Three-panel layout with tabs and output console
  - Theme system with light/dark mode support
- **Improved Tab System**:
  - ExploitationTab with comprehensive exploit development tools
  - AIAssistantTab with AI-powered analysis capabilities
  - Proper shared context support across all tabs
- **Advanced Handlers System**:
  - PyQt6Handler for Qt component management
  - TensorFlowHandler with Intel Arc compatibility
  - TorchHandler with GIL safety measures

### Fixed

- **Critical GUI Launch Issues**:
  - Fixed AttributeError: 'IntellicrackApp' object has no attribute 'parent'
  - Fixed missing QStackedWidget import causing PyQt6 failure
  - Fixed ExploitationTab initialization method (setup_content vs setup_ui)
  - Fixed AIAssistantTab constructor to accept shared_context parameter
  - Fixed Qt.Horizontal/Vertical constants for PyQt6 compatibility
- **Import System Improvements**:
  - Fixed circular import between torch_gil_safety and torch_handler
  - Resolved PyTorch hanging issues during import
  - Enhanced handler-based import system for better reliability
- **Platform Compatibility**:
  - Windows-specific path handling improvements
  - Enhanced virtual environment support (.pixi)
  - Better error handling for missing dependencies

### Changed

- **Project Structure Reorganization**:
  - Test files moved to appropriate subdirectories (tests/unit/, tests/utils/)
  - Enhanced documentation organization in docs/ directory
  - Improved requirements management with requirements/ structure
- **GUI Framework Migration**:
  - Complete transition from PyQt5 to PyQt6
  - Updated all UI components and widgets
  - Enhanced theme management and styling
- **Enhanced Security Research Focus**:
  - Clarified defensive security research purpose
  - Updated disclaimer with explicit focus on authorized testing
  - Enhanced documentation on ethical usage

### Removed

- **Legacy Components**:
  - Removed outdated PyQt5 references
  - Cleaned up obsolete installation scripts
  - Removed incorrect documentation references

## [0.1.0] - 2024-12-01

### Initial Release

- **Core Framework**:
  - Binary analysis and security research platform
  - Multi-format support (PE, ELF, Mach-O)
  - Protection detection capabilities
  - Vulnerability research tools
- **AI Integration**:
  - Multi-provider AI support (OpenAI, Anthropic, Google)
  - Dynamic model fetching and management
  - AI-powered script generation
- **Advanced Features**:
  - Symbolic execution with angr integration
  - Dynamic analysis capabilities
  - Network traffic analysis
  - C2 infrastructure support
- **User Interface**:
  - Professional three-panel GUI layout
  - Hex editor with advanced features
  - Plugin system for extensibility
  - Comprehensive logging system
- **Security Research Tools**:
  - Exploitation framework
  - Protection bypass mechanisms
  - Vulnerability identification
  - License emulation capabilities

### Technical Infrastructure

- **Development Environment**:
  - Python 3.12+ support
  - Windows 11 optimized compatibility
  - GPU acceleration support (NVIDIA, AMD, Intel)
  - Virtual environment management
- **Testing Framework**:
  - Comprehensive test suite
  - Real-world binary fixtures
  - Performance benchmarks
  - Integration tests
- **Documentation System**:
  - Sphinx-based documentation
  - User guides and API reference
  - Architecture documentation
  - Security and ethics guidelines
