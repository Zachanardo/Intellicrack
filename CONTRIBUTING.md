# Contributing to Intellicrack

Thank you for your interest in contributing to Intellicrack! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

Please read and follow our [Code of Conduct](docs/CODE_OF_CONDUCT.md) to ensure a welcoming environment for all contributors.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/intellicrack.git
   cd intellicrack
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/zacharyflint/intellicrack.git
   ```

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -e .
   pip install -e .[dev]  # Install development dependencies
   ```

3. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Project Structure

```
intellicrack/
├── intellicrack/          # Main package source code
│   ├── ai/               # AI and ML components
│   ├── core/             # Core functionality
│   ├── hexview/          # Hex viewer implementation
│   ├── models/           # Model management
│   ├── plugins/          # Plugin system
│   ├── scripts/          # Utility scripts
│   └── ui/               # User interface components
├── tests/                # Test suite
├── docs/                 # Documentation
├── data/                 # Runtime data (gitignored)
└── .github/              # GitHub workflows and templates
```

## Making Changes

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards

3. Write or update tests as needed

4. Update documentation if you've changed functionality

5. Commit your changes with clear, descriptive messages:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```

## Coding Standards

### Python Code Style

- Follow PEP 8 style guide
- Use Black for code formatting (line length: 100)
- Use type hints where applicable
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible

### Import Order

1. Standard library imports
2. Third-party imports
3. Local application imports

Example:
```python
import os
import sys
from typing import Dict, List

import numpy as np
from PyQt5.QtWidgets import QWidget

from intellicrack.core import BinaryAnalyzer
from intellicrack.utils import logger
```

### Naming Conventions

- Classes: `PascalCase`
- Functions/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods/attributes: `_leading_underscore`

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=intellicrack

# Run specific test file
pytest tests/test_core_components.py

# Run tests with verbose output
pytest -v
```

### Writing Tests

- Place tests in the `tests/` directory
- Mirror the source code structure
- Use descriptive test names that explain what is being tested
- Include both positive and negative test cases
- Mock external dependencies

Example:
```python
def test_binary_analyzer_detects_pe_format():
    """Test that BinaryAnalyzer correctly identifies PE files."""
    analyzer = BinaryAnalyzer()
    result = analyzer.analyze("test_data/sample.exe")
    assert result.format == "PE"
```

## Submitting Changes

1. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub:
   - Provide a clear title and description
   - Reference any related issues
   - Include screenshots for UI changes
   - Ensure all tests pass
   - Address review feedback promptly

### Pull Request Checklist

- [ ] Code follows the project's style guidelines
- [ ] Self-review of code completed
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
- [ ] Tests added/updated and passing
- [ ] No new linting warnings
- [ ] Commit messages are clear and descriptive

## Additional Resources

- [Issue Tracker](https://github.com/zacharyflint/intellicrack/issues)
- [Documentation](https://intellicrack.readthedocs.io)
- [Project Wiki](https://github.com/zacharyflint/intellicrack/wiki)

## Questions?

Feel free to open an issue for any questions about contributing. We're here to help!