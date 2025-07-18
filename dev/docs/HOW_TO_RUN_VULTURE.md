# How to Run Vulture on Intellicrack

## Installation

### Windows (using the venv):
```batch
venv\Scripts\pip install vulture
```

### Linux/macOS:
```bash
source venv/bin/activate
pip install vulture
```

## Running Vulture

### Basic Usage

#### Windows:
```batch
venv\Scripts\vulture intellicrack
```

#### Linux/macOS:
```bash
vulture intellicrack
```

### Using the Helper Script

We have a `run_vulture.py` script that scans all Python files:

#### Windows:
```batch
venv\Scripts\python run_vulture.py
```

#### Linux/macOS:
```bash
python run_vulture.py
```

## Advanced Options

### Specific Confidence Threshold
Show only high-confidence unused code (90%+):
```batch
venv\Scripts\vulture intellicrack --min-confidence 90
```

### Exclude Patterns
Exclude test files:
```batch
venv\Scripts\vulture intellicrack --exclude "*/tests/*,*/test_*.py"
```

### Output to File
Save results to a file:
```batch
venv\Scripts\vulture intellicrack > vulture_report.txt
```

### Scan Specific Files
```batch
venv\Scripts\vulture intellicrack/ai/ai_script_generator.py
```

## Understanding Vulture Output

Vulture reports with confidence levels:
- **100% confidence**: Definitely unused (should be fixed)
- **60-90% confidence**: Possibly unused (often false positives from dynamic usage)
- **<60% confidence**: Likely false positives

Example output:
```
intellicrack/ai/ai_tools.py:45: unused function 'get_ai_suggestions' (60% confidence)
intellicrack/logger.py:53: unused variable 'args' (100% confidence)
```

## Common False Positives

Vulture may report false positives for:
- Dynamically imported modules
- Framework callbacks (PyQt5 signals/slots)
- Decorator-wrapped functions
- Plugin system components
- Methods called via getattr()

## Whitelist File

Create a whitelist for known false positives:

```python
# vulture_whitelist.py
import intellicrack.ai.ai_tools
get_ai_suggestions  # used dynamically
```

Run with whitelist:
```batch
venv\Scripts\vulture intellicrack vulture_whitelist.py
```

## Quick Commands

### Full scan with moderate confidence:
```batch
venv\Scripts\vulture intellicrack --min-confidence 70
```

### Scan only AI modules:
```batch
venv\Scripts\vulture intellicrack/ai --min-confidence 80
```

### Generate detailed report:
```batch
venv\Scripts\vulture intellicrack --verbose > vulture_detailed.txt
```