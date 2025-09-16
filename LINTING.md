# Intellicrack Code Linting and Formatting Guide

## Overview

This document describes the linting and formatting tools configured for the Intellicrack project to maintain consistent code quality across different file types.

## Configured Tools

### 1. **Prettier** - Multi-language Formatter
- **Purpose**: Format JSON, YAML, Markdown, and other supported files
- **Config**: `.prettierrc.json`
- **Installation**: `npm install -g prettier`
- **Usage**:
  ```bash
  # Check formatting
  prettier --check "**/*.json"

  # Fix formatting
  prettier --write "**/*.json"

  # List files that would be changed
  prettier --list-different "**/*.{json,yml,md}"
  ```

### 2. **clang-format** - C/C++ Formatter
- **Purpose**: Format C and C++ source files
- **Config**: `.clang-format`
- **Installation**: `winget install LLVM.LLVM`
- **Usage**:
  ```bash
  # Format in place
  clang-format -i -style=file *.cpp

  # Check formatting (dry run)
  clang-format -style=file --dry-run --Werror *.cpp

  # Output formatted version
  clang-format -style=file main.cpp
  ```

### 3. **jq** - JSON Processor and Validator
- **Purpose**: Validate and process JSON files
- **Installation**: `winget install jqlang.jq`
- **Usage**:
  ```bash
  # Validate JSON
  jq . config.json

  # Pretty print JSON
  jq . config.json > formatted.json

  # Validate all JSON files
  fd -e json -x jq . {} \;
  ```

### 4. **jsonlint** - JSON Validator
- **Purpose**: Strict JSON validation with detailed error messages
- **Installation**: `npm install -g jsonlint`
- **Usage**:
  ```bash
  # Validate JSON
  jsonlint config.json

  # Quiet mode (only show errors)
  jsonlint -q config.json

  # Validate all JSON files
  fd -e json -x jsonlint {} \;
  ```

## Configuration Files

### `.prettierrc.json`
```json
{
  "printWidth": 120,
  "tabWidth": 4,
  "useTabs": false,
  "semi": true,
  "singleQuote": false,
  "trailingComma": "es5",
  "bracketSpacing": true,
  "arrowParens": "always",
  "endOfLine": "crlf",
  "overrides": [
    {
      "files": ["*.json", "*.jsonc"],
      "options": {
        "tabWidth": 2,
        "printWidth": 100
      }
    },
    {
      "files": ["*.yml", "*.yaml"],
      "options": {
        "tabWidth": 2,
        "singleQuote": true
      }
    },
    {
      "files": ["*.md"],
      "options": {
        "proseWrap": "preserve",
        "printWidth": 80
      }
    }
  ]
}
```

### `.clang-format`
```yaml
BasedOnStyle: LLVM
IndentWidth: 4
ColumnLimit: 120
UseTab: Never
BreakBeforeBraces: Attach
AllowShortFunctionsOnASingleLine: Empty
AllowShortIfStatementsOnASingleLine: false
IndentCaseLabels: true
SortIncludes: true
IncludeBlocks: Regroup
PointerAlignment: Left
SpaceAfterCStyleCast: false
SpacesInParentheses: false
SpacesInSquareBrackets: false
LineEnding: CRLF
```

## PowerShell Linting Script

A comprehensive PowerShell script `lint.ps1` is provided to run all linters:

```powershell
# Check all files
.\lint.ps1 -Check

# Fix all formatting issues
.\lint.ps1 -Fix

# Check only JSON files
.\lint.ps1 json -Check

# Fix C++ formatting
.\lint.ps1 cpp -Fix

# List formatting issues without fixing
.\lint.ps1 all
```

### Script Options
- **Target**: `json`, `cpp`, `yaml`, `markdown`, `all` (default: `all`)
- **-Fix**: Apply automatic fixes where possible
- **-Check**: Check only mode (don't modify files)
- **Default**: List files that need formatting

## Integration with Development Workflow

### Pre-commit Hooks

Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.1.0
    hooks:
      - id: prettier
        types_or: [json, yaml, markdown]

  - repo: https://github.com/pre-commit/mirrors-clang-format
    rev: v17.0.6
    hooks:
      - id: clang-format
        types_or: [c, c++]
```

### VS Code Integration

Add to `.vscode/settings.json`:
```json
{
  "editor.formatOnSave": true,
  "[json]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[yaml]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[markdown]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[cpp]": {
    "editor.defaultFormatter": "ms-vscode.cpptools"
  },
  "C_Cpp.clang_format_style": "file",
  "prettier.configPath": ".prettierrc.json"
}
```

### CI/CD Integration

Add to GitHub Actions workflow:
```yaml
- name: Check JSON formatting
  run: |
    npm install -g prettier jsonlint
    prettier --check "**/*.{json,yml,md}"
    find . -name "*.json" -type f -exec jsonlint {} \;

- name: Check C++ formatting
  run: |
    sudo apt-get install -y clang-format
    find . -name "*.cpp" -o -name "*.h" | xargs clang-format --dry-run --Werror
```

## Quick Commands

```bash
# Install all linting tools (Windows)
winget install LLVM.LLVM
winget install jqlang.jq
npm install -g prettier jsonlint

# Run all linters
.\lint.ps1 -Check

# Fix all formatting
.\lint.ps1 -Fix

# Validate all JSON files
fd -e json -x jq . {} \;
fd -e json -x jsonlint {} \;

# Format all files with prettier
prettier --write "**/*.{json,yml,md}"

# Format all C++ files
fd -e cpp -e h -x clang-format -i -style=file {} \;
```

## Troubleshooting

### Common Issues

1. **Prettier not parsing TOML files**
   - Expected behavior - Prettier doesn't support TOML format
   - Use dedicated TOML tools if needed

2. **clang-format not found**
   - Install LLVM: `winget install LLVM.LLVM`
   - Or download from: https://releases.llvm.org/

3. **jsonlint command not found**
   - Install via npm: `npm install -g jsonlint`
   - Ensure npm bin directory is in PATH

4. **Line ending conflicts**
   - Project uses CRLF (Windows) line endings
   - Configure Git: `git config core.autocrlf true`

## Best Practices

1. **Run linters before committing**
   ```bash
   .\lint.ps1 -Check
   ```

2. **Fix formatting issues automatically**
   ```bash
   .\lint.ps1 -Fix
   ```

3. **Validate JSON after manual edits**
   ```bash
   jq . config.json && jsonlint config.json
   ```

4. **Keep configurations consistent**
   - All tools configured for 4-space indentation (2 for JSON)
   - Windows line endings (CRLF)
   - 120 character line limit

## Additional Resources

- [Prettier Documentation](https://prettier.io/docs/en/)
- [clang-format Documentation](https://clang.llvm.org/docs/ClangFormat.html)
- [jq Manual](https://stedolan.github.io/jq/manual/)
- [jsonlint Documentation](https://github.com/zaach/jsonlint)
