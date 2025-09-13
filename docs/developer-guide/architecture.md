# Intellicrack Architecture Overview

## High-Level Architecture

Intellicrack follows a modular architecture designed for extensibility and maintainability. The application is structured around core modules that handle different aspects of binary analysis and reverse engineering.

## Core Modules

### Main Entry Point ([`main.py`](../main.py))

The main entry point handles:
- Application initialization and configuration
- Logging setup with file output
- Startup checks and auto-configuration
- GUI launch via the UI module
- Error handling and graceful degradation

Key responsibilities:
- Environment setup (Qt, GPU, security)
- Dependency validation
- Security enforcement initialization

### Core Module ([`core/`](../core/))

Contains core functionality and startup checks:
- Security enforcement
- Startup validation
- Configuration management
- Core utilities and helpers

### UI Module ([`ui/`](../ui/))

Graphical user interface components:
- Main application window ([`main_app.py`](../ui/main_app.py))
- Tab-based interface for different functionalities
- Widgets for specific analysis tasks
- Theme and styling management
- Menu and dialog utilities

Key components:
- Dashboard for overview
- Analysis workspace
- Tools and settings panels
- File management interfaces

### Protection Module ([`protection/`](../protection/))

Handles anti-reverse engineering protection detection and bypass:
- Protection detection algorithms
- Bypass mechanisms
- Report generation
- Unified protection engine
- Advanced protection analysis

### AI Module ([`ai/`](../ai/))

AI-powered analysis and script generation:
- Script generation for Frida and Ghidra
- AI-assisted analysis workflows
- Machine learning models for pattern recognition

### Utilities ([`utils/`](../utils/))

Comprehensive utility libraries organized by functionality:
- **Analysis**: Binary analysis tools, entropy analysis, pattern search
- **Binary**: Binary file handling, PE/ELF analysis, hex utilities
- **Core**: Dependency management, logging, configuration
- **Exploitation**: Exploit development tools, payload handling
- **Protection**: Protection utilities, certificate handling
- **Reporting**: HTML report generation, templates
- **Runtime**: Distributed processing, performance optimization
- **System**: OS detection, process management, file operations

## Data Flow

1. **Input Processing**: Files are loaded through the UI or CLI
2. **Analysis Pipeline**:
   - Static analysis (binary parsing, disassembly)
   - Protection detection
   - Dynamic analysis (if Frida available)
   - AI-assisted analysis
3. **Result Presentation**: Results displayed in UI tabs
4. **Report Generation**: HTML/PDF reports generated

## Dependency Management

Dependencies are managed through [`utils/dependencies.py`](../utils/dependencies.py):
- **Core Dependencies**: Required for basic functionality
  - psutil, requests, pefile, capstone, keystone, unicorn, lief, yara, cryptography
- **Optional Dependencies**: Enhance functionality
  - PyQt6 (GUI), numpy/scikit-learn (ML), frida (dynamic analysis), angr (symbolic execution)

## Plugin Architecture

The application supports plugins through the [`plugins/`](../plugins/) directory:
- Plugin configuration ([`plugin_config.py`](../plugins/plugin_config.py))
- Extensible analysis modules
- Custom tools and integrations

## Configuration System

Configuration is handled through [`utils/config.py`](../utils/config.py):
- Application settings
- Analysis parameters
- UI preferences
- Plugin configurations

## Logging and Monitoring

Logging is implemented in [`utils/logger.py`](../utils/logger.py):
- File-based logging with rotation
- Multiple log levels
- Performance monitoring
- Error tracking

## Security Considerations

Security features include:
- Security enforcement ([`core/security_enforcement.py`](../core/security_enforcement.py))
- Safe subprocess execution
- Input validation
- Dependency verification

## Extension Points

The architecture provides several extension points:
- Plugin system for custom analysis tools
- Handler system for different analysis types
- Widget system for custom UI components
- Report generation templates

## Build and Deployment

- Entry point: [`main.py`](../main.py) or [`__main__.py`](../__main__.py)
- Dependencies: Managed via pip, no build process required
- Cross-platform: Windows, Linux, macOS support
- Portable: No installation required, can run from source

## Development Guidelines

- Modular design with clear separation of concerns
- Consistent error handling and logging
- Type hints and documentation
- Unit tests for core functionality
- Plugin-based extensibility

## Performance Considerations

- Lazy loading of optional modules
- Background processing for heavy analysis
- Memory-efficient data structures
- GPU acceleration support (optional)

This architecture ensures Intellicrack remains maintainable, extensible, and performant while providing comprehensive binary analysis capabilities.
