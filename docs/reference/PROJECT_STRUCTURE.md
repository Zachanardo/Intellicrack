# Intellicrack Project Structure

## Root Directory Layout

```
intellicrack/
├── .github/                    # GitHub-specific configuration
│   ├── workflows/             # GitHub Actions CI/CD
│   └── ISSUE_TEMPLATE/        # Issue templates
├── assets/                    # Application assets (icons, images)
├── c2_downloads/              # Command & Control download storage
├── c2_uploads/                # Command & Control upload storage
├── cache/                     # Application cache
├── config/                    # Configuration files
├── data/                      # Application data storage
├── dependencies/              # Dependency installation scripts
├── dev/                       # Development scripts and reports
├── docs/                      # Documentation (Sphinx)
├── examples/                  # Example scripts and usage
├── intellicrack/              # Main application package
├── logs/                      # Application logs
├── models/                    # Machine learning models
├── project-docs/              # Project analysis documents
├── reports/                   # Generated reports
├── requirements/              # Dependency requirements
├── samples/                   # Binary samples (gitignored)

├── ssl_certificates/          # SSL certificates
├── tests/                     # Test suite
├── tools/                     # External tools integration
└── visualizations/            # Generated visualizations
```

## Key Files in Root

### Configuration Files
- `.coveragerc` - Coverage.py configuration
- `.dockerignore` - Docker ignore patterns
- `.editorconfig` - Editor configuration
- `.gitignore` - Git ignore patterns
- `.pre-commit-config.yaml` - Pre-commit hooks
- `.readthedocs.yaml` - Read the Docs configuration
- `docker-compose.yml` - Docker Compose configuration
- `Dockerfile` - Docker container definition
- `pyproject.toml` - Python project configuration
- `pytest.ini` - Pytest configuration

### Documentation
- `CLAUDE.md` - AI assistant context
- `LICENSE` - GPL-3.0 license
- `README.md` - Project readme
- `PROJECT_STRUCTURE.md` - This file

### Build/Package Files
- `MANIFEST.in` - Package manifest
- `Makefile` - Build automation

### Entry Points
- `launch_intellicrack.py` - Python launcher
- `RUN_INTELLICRACK.bat` - Windows launcher

## Main Package Structure

### intellicrack/
The main application package containing:

- `ai/` - AI/ML integration modules
- `cli/` - Command-line interface
- `core/` - Core functionality
  - `analysis/` - Binary analysis engines
  - `anti_analysis/` - Anti-analysis detection
  - `c2/` - Command & Control infrastructure
  - `exploitation/` - Exploitation modules
  - `network/` - Network analysis
  - `patching/` - Binary patching
  - `processing/` - Distributed processing
  - `protection_bypass/` - Protection bypass
  - `reporting/` - Report generation
  - `vulnerability_research/` - Vulnerability research
- `hexview/` - Professional hex editor
- `plugins/` - Plugin system
- `ui/` - User interface components
- `utils/` - Utility modules organized by function

## Directory Purposes

### Development & Documentation
- `dev/` - Development scripts, linting tools, analysis reports
- `docs/` - Sphinx documentation with API references
- `project-docs/` - Project-specific analysis and planning documents

### Runtime Directories
- `cache/` - Temporary cache files
- `data/` - Persistent application data
- `logs/` - Application and operation logs
- `reports/` - Generated analysis reports
- `visualizations/` - Generated charts and graphs

### Dependencies & Tools
- `dependencies/` - Installation scripts for external tools
- `tools/` - External tool binaries (Ghidra, Radare2)
- `requirements/` - Modular Python requirements

### Testing
- `tests/` - Comprehensive test suite
  - `unit/` - Unit tests
  - `integration/` - Integration tests
  - `test_programs/` - Test binary programs

### Scripts & Examples
- `intellicrack/intellicrack/scripts/` - Utility scripts organized by type
  - `cli/` - CLI enhancement scripts
  - `frida/` - Frida scripts
  - `ghidra/` - Ghidra scripts
  - `radare2/` - Radare2 scripts
- `examples/` - Example usage scripts

### Security & Certificates
- `ssl_certificates/` - SSL/TLS certificates for secure communication
- `samples/` - Binary samples for testing (gitignored for security)

## File Organization Rules

1. **Python modules** - All Python code in `intellicrack/` package
2. **Documentation** - User docs in `docs/`, project docs in `project-docs/`
3. **Configuration** - Root level for tool configs, `config/` for app configs
4. **Scripts** - Organized by type in `intellicrack/intellicrack/scripts/`
5. **Tests** - Mirror package structure in `tests/`
6. **Generated files** - Output to appropriate directories (logs/, reports/, etc.)
7. **Temporary files** - Use `cache/` directory
8. **Binary samples** - Store in `samples/` (gitignored)

## Clean Root Directory

The root directory now contains only:
- Essential configuration files
- Documentation files (README, LICENSE, etc.)
- Entry point scripts
- Standard Python project files

All other files have been organized into appropriate subdirectories for better maintainability.
