# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Organized project structure following Python best practices
- Created data/ directory for runtime files (database, uploads, downloads, cache)
- Added .github/ directory structure for GitHub workflows and templates
- Added CHANGELOG.md for tracking version history
- Added CONTRIBUTING.md with development guidelines

### Changed
- Moved runtime files (c2_sessions.db, c2_uploads/, c2_downloads/, cache/) to data/ directory
- Updated session_manager.py to use new data directory paths with migration support
- Consolidated scripts directories - moved all scripts from root /scripts/ to /intellicrack/scripts/
- Moved Sphinx documentation artifacts to docs/ directory
- Organized scripts into subdirectories (frida/, ghidra/, fixes/, etc.)

### Removed
- Removed duplicate conf.py from root (kept docs/conf.py)
- Removed empty models/ directory from root
- Removed =2.0.0 file (pip install output)
- Removed ML scripts directory as ML functionality was removed

## [0.1.0] - 2024-06-30

### Added
- Initial release of Intellicrack
- Binary analysis and security research framework
- AI-powered script generation
- Protection detection and bypass capabilities
- C2 infrastructure support
- Hex viewer with advanced features
- Plugin system for extensibility