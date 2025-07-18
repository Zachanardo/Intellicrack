# Intellicrack Documentation

Welcome to the Intellicrack documentation! This directory contains comprehensive documentation for users and developers.

## Documentation Structure

### Getting Started
- [Installation Guide](INSTALLATION.md) - How to install and set up Intellicrack
- [Quick Start Guide](usage/ai_assistant.md) - Get started with AI features

### User Guides (`usage/`)
- [AI Assistant](usage/ai_assistant.md) - AI-powered features and model configuration
- [Basic Analysis](usage/basic_analysis.md) - Getting started with binary analysis
- [Patching Guide](usage/patching.md) - How to patch binaries
- [CLI Usage](usage/cli_usage.md) - Command-line interface guide
- [API Model Import](usage/api_model_import.md) - Model management features

### Integration Guides (`guides/`)
- [Frida Integration](guides/FRIDA_INTEGRATION_GUIDE.md) - Dynamic instrumentation with Frida
- [Radare2 Integration](guides/RADARE2_INTEGRATION_GUIDE.md) - Using Radare2 with Intellicrack
- [Radare2 Quick Reference](guides/RADARE2_QUICK_REFERENCE.md) - Common Radare2 commands
- [QEMU Setup](guides/QEMU_SETUP_GUIDE.md) - Setting up QEMU for dynamic analysis
- [Symbolic Execution](guides/SYMBOLIC_EXECUTION.md) - Using symbolic execution engines
- [Secrets Management](guides/SECRETS_MANAGEMENT.md) - Handling sensitive data

### Reference Documentation (`reference/`)
- [AI Models Quick Reference](reference/AI_MODELS_QUICK_REFERENCE.md) - AI provider setup and model selection
- [API Reference](reference/api_reference.md) - Complete API documentation
- [Network Protocols](reference/network_protocols.md) - Network analysis features
- [Project Structure](reference/PROJECT_STRUCTURE.md) - Codebase organization

### Architecture & Development (`architecture/`, `development/`)
- [Architecture Overview](architecture/overview.md) - System architecture
- [Plugin System](architecture/plugin_system.md) - Plugin architecture
- [Plugin Development](development/plugins.md) - Creating custom plugins

### ICP Integration (`icp_integration/`)
- User guides, deployment, and technical documentation for the ICP protection engine

### Deployment (`deployment/`)
- [Docker Deployment](deployment/docker.md) - Running in Docker
- [Production Setup](deployment/production.md) - Production deployment

### API Documentation (`api/`)
- Auto-generated API documentation from source code
- [Python API](api/python_api.md) - Python API reference
- [REST API](api/rest_api.md) - REST API endpoints

### Contributing
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute (in project root)
- [Code of Conduct](../CODE_OF_CONDUCT.md) - Community guidelines (in project root)

## Building Documentation

The documentation uses Sphinx. To build:

```bash
# Install documentation dependencies
pip install -r requirements.txt

# Build HTML documentation
python build_docs.py
# or
./build_docs.sh  # Linux/macOS
./build_docs.bat # Windows
```

The built documentation will be available in `_build/html/`.

## Documentation Standards

When contributing documentation:
1. Use clear, concise language
2. Include practical examples
3. Keep formatting consistent
4. Update index files when adding new documents
5. Test all code examples

## Quick Links

- [AI Quick Reference](reference/AI_MODELS_QUICK_REFERENCE.md) - AI provider setup
- Main documentation index: [index.md](index.md) or [index.rst](index.rst)