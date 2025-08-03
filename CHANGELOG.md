# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Enhanced AI Model Selection**: Support for 16+ AI providers with dynamic model fetching
  - Comprehensive provider support: OpenAI, Anthropic, Google Gemini, Local (Ollama), Azure OpenAI, AWS Bedrock, Cohere, Hugging Face, OpenRouter, Together AI, Perplexity, Groq, Replicate, DeepInfra, Anyscale, LM Studio
  - Dynamic model fetching: Automatically retrieves latest available models when API key is provided
  - Auto-refresh feature: Models update automatically 1 second after entering API key
  - Manual refresh button for on-demand model list updates
  - Comprehensive fallback model lists with latest models (GPT-4o, Claude 3.5, Gemini 2.0, etc.)
- **New Documentation**:
  - AI Assistant User Guide (docs/usage/ai_assistant.md) with comprehensive provider setup instructions
  - AI Models Quick Reference (docs/AI_MODELS_QUICK_REFERENCE.md) with API key requirements and model recommendations
  - Updated main documentation index to include AI guides

### Fixed
- **Theme Manager Error**: Fixed AttributeError where `theme_manager.apply_theme()` was called instead of correct `theme_manager.set_theme()` method
- Fixed F405 linting errors by replacing star imports with explicit imports across multiple modules
- Resolved import resolution issues in utils/additional_runners.py
- Fixed import resolution in utils/analysis/__init__.py
- Fixed import resolution in utils/config.py
- Fixed import resolution in utils/core/__init__.py
- Fixed import resolution in utils/exploit_common.py
- Fixed import resolution in utils/ghidra_script_manager.py
- Fixed import resolution in utils/license_response_templates.py
- Fixed import resolution in utils/network_api_common.py
- Fixed syntax errors in core/patching/payload_generator.py string concatenation
- Enhanced code quality and linting compliance across the codebase
- Fixed high severity vulnerabilities in dependencies
- Updated security documentation with correct project setup
- Improved WSL/Windows virtual environment compatibility

### Added
- Comprehensive code implementation across all modules with real functionality
- Full implementation of 33+ advanced security research functions
- Enhanced AI integration with multiple LLM backend support
- Advanced binary analysis capabilities with radare2 integration
- Sophisticated protection detection and bypass mechanisms
- ML-based vulnerability prediction and analysis
- Enhanced C2 infrastructure with secure communication protocols
- Advanced payload generation with polymorphic capabilities
- Comprehensive frida script generation and management
- Real-time network traffic analysis and interception
- Hardware emulation for dongles and TPM bypassing
- Advanced memory forensics and process analysis
- Distributed analysis framework for scalability
- GPU acceleration support for intensive computations
- Enhanced plugin system with dynamic loading
- Comprehensive test suite with real-world validation
- Advanced UI components with professional three-panel layout
- Secure secrets management system
- Enhanced documentation and configuration management
- Organized project structure following Python best practices
- Created data/ directory for runtime files (database, uploads, downloads, cache)
- Added .github/ directory structure for GitHub workflows and templates
- Added CHANGELOG.md for tracking version history
- Added CONTRIBUTING.md with development guidelines
- New requirements structure in requirements/ directory
- Enhanced virtual environment support for WSL and Windows

### Changed
- Moved runtime files (c2_sessions.db, c2_uploads/, c2_downloads/, cache/) to data/ directory
- Updated session_manager.py to use new data directory paths with migration support
- Consolidated scripts directories - moved all scripts from root /scripts/ to /intellicrack/scripts/
- Moved Sphinx documentation artifacts to docs/ directory
- Organized scripts into subdirectories (frida/, ghidra/, fixes/, etc.)
- Migrated from pyproject.toml to requirements.txt structure
- Updated all module imports to use explicit imports instead of star imports
- Enhanced error handling and fallback mechanisms across all modules
- Improved platform compatibility and dependency management
- Refactored AI model management with lazy loading and caching
- Enhanced UI responsiveness and user experience
- Streamlined configuration management system

### Removed
- Removed duplicate conf.py from root (kept docs/conf.py)
- Removed empty models/ directory from root
- Removed =2.0.0 file (pip install output)
- Removed legacy ICP engine tools and binaries
- Removed obsolete DLL files and Windows-specific artifacts
- Removed old pyproject.toml in favor of requirements structure
- Removed legacy ML model guide (superseded by implementation)
- Cleaned up redundant signature files and test artifacts

## [0.1.0] - 2024-06-30

### Added
- Initial release of Intellicrack
- Binary analysis and security research framework
- AI-powered script generation
- Protection detection and bypass capabilities
- C2 infrastructure support
- Hex viewer with advanced features
- Plugin system for extensibility
