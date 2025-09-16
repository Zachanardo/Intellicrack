# Symbolic Execution in Intellicrack

## Overview

Intellicrack supports multiple symbolic execution engines with automatic platform detection and graceful fallback.

## Engine Priority and Availability

### 1. angr (Primary Engine)
- **Platforms**: Windows 11
- **Installation**: Included in base requirements
- **Features**: Full symbolic execution, path exploration, constraint solving
- **UI Option**: "Symbolic Execution" button

### 2. manticore (Secondary Engine - Not Available on Windows)
- **Platforms**: Not supported on Windows 11
- **Installation**: Not available for Windows platforms
- **Features**: N/A for Windows users
- **UI Option**: Disabled on Windows 11

### 3. simconcolic (Fallback Engine)
- **Platforms**: Windows 11 (built-in)
- **Installation**: No installation needed
- **Features**: Basic symbolic execution, limited functionality

## Platform-Specific Behavior

### Windows 11 Users
1. **Available Engines**: angr (full features), simconcolic (fallback)
2. **Recommended**: Always use "Symbolic Execution" (angr)
3. **UI Behavior**:
   - "Concolic Execution" shows informative message directing to angr
   - No manticore errors or missing dependency warnings
   - Automatic fallback to simconcolic if angr fails

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
    pass  # Expected on Windows 11
```

### Execution Priority
```python
if execution_engines['angr']:
    # Use angr (preferred)
    perform_angr_analysis()
elif execution_engines['simconcolic']:
    # Use simconcolic (minimal fallback)
    perform_basic_analysis()
else:
    # No symbolic execution engine available
    show_error_message()
```

## Feature Comparison

| Feature | angr | simconcolic |
|---------|------|-------------|
| Windows 11 Support | ✅ | ✅ |
| Path Exploration | ✅ | ⚠️ |
| Constraint Solving | ✅ | ⚠️ |
| License Bypass | ✅ | ❌ |
| Memory Analysis | ✅ | ❌ |
| Hook Support | ✅ | ⚠️ |
| Speed | Fast | Fast |

## Troubleshooting

### "Manticore not available" on Windows 11
This is expected. Manticore is not supported on Windows platforms. Use the "Symbolic Execution" option which uses angr.

### angr fails to load
Check that you have:
1. Proper Python version (3.12+)
2. Updated pip: `pip install --upgrade pip`
3. Visual C++ Build Tools for Windows 11
4. Reinstall angr: `pip install --force-reinstall angr`

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
