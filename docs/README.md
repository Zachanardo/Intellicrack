# Intellicrack Documentation

Welcome to the Intellicrack documentation! This directory contains comprehensive documentation for users and developers.

## Documentation Structure

### Core Documentation
- [Installation Guide](INSTALLATION.md) - How to install and set up Intellicrack
- [API Reference](api_reference.md) - Complete API documentation
- [CLI Usage](cli_usage.md) - Command-line interface guide
- [Contributing](CONTRIBUTING.md) - Guidelines for contributing to the project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines
- [Project Structure](PROJECT_STRUCTURE.md) - Overview of the codebase organization

### User Guides
- [Basic Analysis](usage/basic_analysis.md) - Getting started with binary analysis
- [Patching Guide](usage/patching.md) - How to patch binaries
- [Protection Analysis](icp_integration/user/protection_analysis.md) - Analyzing binary protections
- [Result Interpretation](icp_integration/user/result_interpretation.md) - Understanding analysis results
- [Scan Modes](icp_integration/user/scan_modes.md) - Different scanning options

### Integration Guides
- [Frida Integration](FRIDA_INTEGRATION_GUIDE.md) - Using Frida with Intellicrack
- [Radare2 Integration](RADARE2_INTEGRATION_GUIDE.md) - Using Radare2 with Intellicrack
- [Radare2 Quick Reference](RADARE2_QUICK_REFERENCE.md) - Common Radare2 commands
- [QEMU Setup](QEMU_SETUP_GUIDE.md) - Setting up QEMU for dynamic analysis

### Architecture & Development
- [Architecture Overview](architecture/overview.md) - System architecture
- [Plugin System](architecture/plugin_system.md) - Plugin development guide
- [Development Plugins](development/plugins.md) - Creating custom plugins
- [Secrets Management](SECRETS_MANAGEMENT.md) - Handling sensitive data
- [Network Protocols](network_protocols.md) - Network analysis features

### API Documentation
- [Python API](api/python_api.md) - Python API reference
- [REST API](api/rest_api.md) - REST API endpoints
- [Model Import API](api_model_import.md) - Model management API
- [Module Reference](api/modules.rst) - Complete module documentation

### ICP Integration
- [Installation](icp_integration/deployment/installation.md) - ICP engine setup
- [Architecture](icp_integration/technical/architecture.md) - ICP technical details
- [API Reference](icp_integration/technical/api_reference.md) - ICP API documentation
- [Testing Framework](icp_integration/technical/testing_framework.md) - ICP testing guide

### Deployment
- [Docker Deployment](deployment/docker.md) - Running Intellicrack in Docker
- [Production Setup](deployment/production.md) - Production deployment guide

## Building Documentation

The documentation uses Sphinx. To build the HTML documentation:

```bash
cd docs
make html
```

The built documentation will be available in `_build/html/`.

## Contributing to Documentation

When contributing documentation:
1. Follow the existing structure and formatting
2. Include practical examples where appropriate
3. Keep language clear and concise
4. Update the relevant index files when adding new documents

For more information, see our [Contributing Guide](CONTRIBUTING.md).