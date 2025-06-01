# Contributing to Intellicrack

Thank you for your interest in contributing to Intellicrack! This guide will help you get started with contributing to the project.

## Getting Started

### Prerequisites

1. **Python 3.8+** installed
2. **Git** for version control
3. **Development environment** (VS Code, PyCharm, etc.)
4. **Dependencies** installed via `dependencies\install_dependencies.bat`

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/intellicrack.git
cd intellicrack

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Code Style Guidelines

### Python Style

We follow PEP 8 with these specific conventions:

```python
# Class names: PascalCase
class BinaryAnalyzer:
    pass

# Function/method names: snake_case
def analyze_binary(file_path: str) -> dict:
    pass

# Constants: UPPER_SNAKE_CASE
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Private methods: leading underscore
def _internal_helper(self):
    pass
```

### Type Hints

Always use type hints for function parameters and return values:

```python
from typing import List, Dict, Optional, Union

def process_data(
    binary_data: bytes,
    options: Optional[Dict[str, Any]] = None
) -> Union[Dict[str, Any], None]:
    """Process binary data with optional configuration."""
    pass
```

### Docstrings

Use Google-style docstrings for all public functions and classes:

```python
def analyze_pe_file(file_path: str, deep_scan: bool = False) -> dict:
    """Analyze a PE (Portable Executable) file.
    
    Args:
        file_path: Path to the PE file to analyze
        deep_scan: Whether to perform deep analysis (slower)
    
    Returns:
        Dictionary containing analysis results with keys:
        - headers: PE header information
        - imports: Imported functions
        - exports: Exported functions
        - vulnerabilities: List of detected vulnerabilities
    
    Raises:
        FileNotFoundError: If file_path doesn't exist
        InvalidPEError: If file is not a valid PE
    """
    pass
```

## Development Process

### 1. Creating Issues

Before starting work:
- Check existing issues to avoid duplicates
- Create a detailed issue describing the problem/feature
- Use appropriate labels (bug, enhancement, documentation)

### 2. Branching Strategy

```bash
# Feature branches
git checkout -b feature/add-new-analyzer

# Bug fixes
git checkout -b fix/memory-leak-in-parser

# Documentation
git checkout -b docs/update-api-guide
```

### 3. Making Changes

#### Code Organization

Follow the existing package structure:
- `intellicrack/core/`: Core functionality
- `intellicrack/ui/`: GUI components
- `intellicrack/utils/`: Utility functions
- `intellicrack/plugins/`: Plugin system

#### Adding New Features

1. **Create the implementation**:
```python
# intellicrack/core/analysis/new_analyzer.py
class NewAnalyzer:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def analyze(self, data: bytes) -> dict:
        # Implementation
        pass
```

2. **Add tests**:
```python
# tests/core/analysis/test_new_analyzer.py
import unittest
from intellicrack.core.analysis import NewAnalyzer

class TestNewAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NewAnalyzer()
    
    def test_basic_analysis(self):
        result = self.analyzer.analyze(b"test data")
        self.assertIsNotNone(result)
```

3. **Update documentation**:
- Add docstrings to all public methods
- Update relevant .md files if needed
- Add examples if applicable

### 4. Testing

#### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/core/test_analysis.py

# Run with coverage
python -m pytest --cov=intellicrack tests/
```

#### Writing Tests

- Test both positive and negative cases
- Mock external dependencies
- Aim for >80% code coverage
- Use descriptive test names

```python
def test_analyze_binary_with_invalid_input_raises_exception(self):
    """Test that analyzing invalid input raises appropriate exception."""
    with self.assertRaises(InvalidBinaryError):
        self.analyzer.analyze(b"invalid")
```

### 5. Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Examples:
```
feat(analysis): add support for Mach-O fat binaries

- Implement fat binary parsing
- Add architecture detection
- Update UI to show multiple architectures

Closes #123
```

```
fix(ui): resolve crash when loading large files

Files over 1GB caused memory overflow. Now using
streaming approach for large file handling.

Fixes #456
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

## Pull Request Process

### 1. Before Submitting

- [ ] All tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### 2. PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Manual testing completed
- [ ] No regressions identified

## Screenshots (if applicable)
Add screenshots for UI changes

## Related Issues
Closes #XXX
```

### 3. Review Process

- PRs require at least one approval
- Address all review comments
- Keep PR scope focused
- Update PR based on feedback

## Debugging Tips

### Common Issues

1. **Import Errors**:
```python
# Add to top of file for debugging
import sys
print(f"Python path: {sys.path}")
print(f"Current dir: {os.getcwd()}")
```

2. **Qt/GUI Issues**:
```python
# Enable Qt debugging
import os
os.environ['QT_DEBUG_PLUGINS'] = '1'
```

3. **Memory Issues**:
```python
# Profile memory usage
from memory_profiler import profile

@profile
def memory_intensive_function():
    pass
```

### Logging

Use the built-in logger for debugging:

```python
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

logger.debug("Detailed debug information")
logger.info("General information")
logger.warning("Warning messages")
logger.error("Error messages")
```

## Performance Guidelines

### Optimization Tips

1. **Large File Handling**:
```python
# Use generators for large files
def read_large_file(path: str):
    with open(path, 'rb') as f:
        while chunk := f.read(1024 * 1024):  # 1MB chunks
            yield chunk
```

2. **Caching**:
```python
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_computation(param: str) -> dict:
    # Cached computation
    pass
```

3. **Parallel Processing**:
```python
from concurrent.futures import ThreadPoolExecutor

def process_multiple_files(file_paths: List[str]):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = executor.map(analyze_file, file_paths)
    return list(results)
```

## Security Considerations

### Input Validation

Always validate user input:

```python
def load_binary(file_path: str) -> bytes:
    # Validate path
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Check file size
    size = os.path.getsize(file_path)
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {size} bytes")
    
    # Validate file type
    if not is_valid_binary(file_path):
        raise InvalidBinaryError("Not a valid binary file")
    
    return read_file_safely(file_path)
```

### Sandboxing

For untrusted code execution:

```python
import subprocess
import tempfile

def run_untrusted_plugin(plugin_code: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        # Run in isolated environment
        result = subprocess.run(
            [sys.executable, "-m", "plugin_runner", plugin_code],
            cwd=tmpdir,
            capture_output=True,
            timeout=30,  # 30 second timeout
            check=False
        )
    return result
```

## Documentation Standards

### Code Documentation

- Every module needs a module-level docstring
- Public APIs must be documented
- Include usage examples for complex features
- Keep documentation up to date with code

### User Documentation

When adding user-facing features:
1. Update relevant guides in `docs/`
2. Add screenshots if UI-related
3. Include common use cases
4. Document any configuration options

## Release Process

### Version Numbering

We use semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in setup.py
- [ ] Release notes prepared

## Getting Help

### Resources

- **Documentation**: Check `docs/` folder
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions for questions

### Communication

- Be respectful and constructive
- Provide context and examples
- Follow up on your issues/PRs
- Help others when you can

## Recognition

Contributors are recognized in:
- Release notes
- Contributors file
- Project documentation

Thank you for contributing to Intellicrack!
