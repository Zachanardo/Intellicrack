# Linting Setup Guide

## Overview

Intellicrack uses comprehensive linting for Python, JavaScript, Java, and Markdown files to maintain code quality and consistency.

## Available Linters

### Python - Ruff

Fast, comprehensive Python linter and formatter.

- **Check**: `just lint`
- **Fix**: `just lint-fix`
- **Config**: `pyproject.toml`

### JavaScript - ESLint

Modern JavaScript linter with Frida-specific globals.

- **Check**: `just lint-js`
- **Fix**: `just lint-js-fix`
- **Config**: `eslint.config.js`

### Java - Checkstyle

Terminal-based Java linter similar to ruff.

- **Check**: `just lint-java`
- **Config**: `tools/checkstyle/intellicrack_checks.xml`
- **Location**: `tools/checkstyle/checkstyle.jar`

### Markdown - Markdownlint

Comprehensive markdown linter for documentation.

- **Check**: `just lint-md`
- **Fix**: `just lint-md-fix`
- **Config**: `.markdownlint.json`

## Quick Commands

```bash
# Lint all file types
just lint-all

# Fix all auto-fixable issues
just lint-all-fix

# Individual linters
just lint        # Python
just lint-js     # JavaScript
just lint-java   # Java
just lint-md     # Markdown
```

## Installation

### Python (Ruff)

```bash
pip install ruff
```

### JavaScript (ESLint)

```bash
npm install -D eslint
```

### Java (Checkstyle)

Already included in `tools/checkstyle/` directory.

### Markdown (Markdownlint)

```bash
npm install -g markdownlint-cli
```

## Configuration Files

- **Python**: `pyproject.toml` - Ruff configuration
- **JavaScript**: `eslint.config.js` - ESLint v9 configuration
- **Java**: `tools/checkstyle/intellicrack_checks.xml` - Custom Checkstyle rules
- **Markdown**: `.markdownlint.json` - Markdownlint rules

## Current Status

- **Python**: 4,851 errors detected (2,711 auto-fixable)
- **JavaScript**: 478 style issues (all auto-fixable)
- **Java**: 2,056 issues across Ghidra scripts
- **Markdown**: Multiple formatting issues in documentation

## CI/CD Integration

All linters can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Lint Python
  run: just lint

- name: Lint JavaScript
  run: just lint-js

- name: Lint Java
  run: just lint-java

- name: Lint Markdown
  run: just lint-md
```