# Symbolic Execution in Intellicrack

## Overview

Intellicrack supports multiple symbolic execution engines with automatic platform detection and graceful fallback.

## Engine Priority and Availability

### 1. angr (Primary Engine - All Platforms)
- **Platforms**: Windows, Linux, macOS
- **Installation**: Included in base requirements
- **Features**: Full symbolic execution, path exploration, constraint solving
- **UI Option**: "Symbolic Execution" button

### 2. manticore (Secondary Engine - Linux Only)
- **Platforms**: Linux/Unix only
- **Installation**: Automatic on Linux via `pip install intellicrack`
- **Features**: Native EVM support, detailed state management
- **UI Option**: "Concolic Execution" button (Linux only)

### 3. simconcolic (Fallback Engine)
- **Platforms**: All (built-in)
- **Installation**: No installation needed
- **Features**: Basic symbolic execution, limited functionality

## Platform-Specific Behavior

### Windows Users
1. **Available Engines**: angr (full features), simconcolic (fallback)
2. **Recommended**: Always use "Symbolic Execution" (angr)
3. **UI Behavior**:
   - "Concolic Execution" shows informative message directing to angr
   - No manticore errors or missing dependency warnings

### Linux Users
1. **Available Engines**: angr, manticore, simconcolic
2. **Recommended**: angr for general use, manticore for specific needs
3. **UI Behavior**:
   - Both "Symbolic Execution" and "Concolic Execution" available
   - Automatic fallback if one engine fails

## Code Architecture

### Engine Detection (main_app.py)
```python
execution_engines = {
    'manticore': False,
    'angr': False,
    'triton': False,
    'z3': False,
    'simconcolic': False
}

# Check each engine availability
try:
    import angr
    execution_engines['angr'] = True
except ImportError:
    pass

try:
    from manticore.native import Manticore
    execution_engines['manticore'] = True
except ImportError:
    pass  # Expected on Windows
```

### Execution Priority
```python
if execution_engines['angr']:
    # Use angr (preferred)
    perform_angr_analysis()
elif execution_engines['manticore']:
    # Use manticore (Linux fallback)
    perform_manticore_analysis()
elif execution_engines['simconcolic']:
    # Use simconcolic (minimal fallback)
    perform_basic_analysis()
```

## Feature Comparison

| Feature | angr | manticore | simconcolic |
|---------|------|-----------|-------------|
| Windows Support | ✅ | ❌ | ✅ |
| Linux Support | ✅ | ✅ | ✅ |
| Path Exploration | ✅ | ✅ | ⚠️ |
| Constraint Solving | ✅ | ✅ | ⚠️ |
| License Bypass | ✅ | ✅ | ❌ |
| Memory Analysis | ✅ | ✅ | ❌ |
| Hook Support | ✅ | ✅ | ⚠️ |
| Speed | Fast | Slow | Fast |

## Troubleshooting

### "Manticore not available" on Windows
This is expected. Use the "Symbolic Execution" option which uses angr.

### "Manticore not available" on Linux
Install with: `pip install manticore`

### Both engines fail
Check that you have:
1. Proper Python version (3.10-3.12)
2. Updated pip: `pip install --upgrade pip`
3. C++ compiler for binary dependencies

## API Usage

### Using angr (Recommended)
```python
from intellicrack.core.analysis import SymbolicAnalyzer

analyzer = SymbolicAnalyzer(engine='angr')
result = analyzer.analyze_binary('target.exe')
```

### Automatic Engine Selection
```python
from intellicrack.core.analysis import SymbolicAnalyzer

# Automatically selects best available engine
analyzer = SymbolicAnalyzer()
result = analyzer.analyze_binary('target.exe')
```
