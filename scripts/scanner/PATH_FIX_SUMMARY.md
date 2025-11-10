# Frida/Ghidra Script Path Centralization - Fix Summary

## Problem Identified

Multiple files were creating/using incorrect script paths:

- `intellicrack/core/certificate/frida_scripts`
- `intellicrack/plugins/frida_scripts`
- `intellicrack/plugins/ghidra_scripts`

**These directories should NOT exist.** All scripts must use centralized
locations:

- `D:\Intellicrack\intellicrack\scripts\frida`
- `D:\Intellicrack\intellicrack\scripts\ghidra`

---

## Files Fixed

### 1. **`utils/core/plugin_paths.py`**

**Lines 70, 80** - Fixed incorrect path resolution

**BEFORE:**

```python
return Path(get_resource_path("intellicrack/intellicrack/scripts/frida"))  # WRONG: double intellicrack
return Path(get_resource_path("intellicrack/intellicrack/scripts/ghidra"))  # WRONG: double intellicrack
```

**AFTER:**

```python
return Path(get_resource_path("scripts/frida"))  # CORRECT
return Path(get_resource_path("scripts/ghidra"))  # CORRECT
```

---

### 2. **`core/certificate/frida_cert_hooks.py`**

**Line 127** - Added import  
**Line 194** - Fixed SCRIPT_DIR

**BEFORE:**

```python
SCRIPT_DIR = Path(__file__).parent / "frida_scripts"  # WRONG: creates local dir
```

**AFTER:**

```python
from intellicrack.utils.core.plugin_paths import get_frida_scripts_dir

SCRIPT_DIR = get_frida_scripts_dir()  # CORRECT: uses centralized dir
```

---

### 3. **`ui/main_app.py`**

**Line 91** - Added import  
**Lines 1278-1279** - Fixed plugin directories

**BEFORE:**

```python
self.PLUGIN_TYPE_FRIDA: plugin_base_dir / "frida_scripts",    # WRONG
self.PLUGIN_TYPE_GHIDRA: plugin_base_dir / "ghidra_scripts",  # WRONG
```

**AFTER:**

```python
from intellicrack.utils.core.plugin_paths import get_frida_scripts_dir, get_ghidra_scripts_dir

self.PLUGIN_TYPE_FRIDA: get_frida_scripts_dir(),   # CORRECT
self.PLUGIN_TYPE_GHIDRA: get_ghidra_scripts_dir(), # CORRECT
```

---

### 4. **`plugins/plugin_system.py`**

**Line 29** - Added import  
**Lines 1253, 1298, 1356, 1359, 1393, 1396** - Fixed all hardcoded paths

**BEFORE:**

```python
for subdir in ["frida_scripts", "ghidra_scripts"]:  # WRONG: checking wrong locations
    plugin_path = os.path.join(self.plugin_dir, subdir)

dest_dir = os.path.join(self.plugin_dir, "frida_scripts")   # WRONG
dest_dir = os.path.join(self.plugin_dir, "ghidra_scripts")  # WRONG
```

**AFTER:**

```python
from intellicrack.utils.core.plugin_paths import get_frida_scripts_dir, get_ghidra_scripts_dir

# Check centralized script directories
dest_dir = str(get_frida_scripts_dir())   # CORRECT
dest_dir = str(get_ghidra_scripts_dir())  # CORRECT
```

---

### 5. **`core/analysis/cross_tool_orchestrator.py`**

**Line 3** - Added import  
**Line 1094** - Fixed Ghidra scripts path

**BEFORE:**

```python
"-scriptPath",
os.path.join(os.path.dirname(__file__), "ghidra_scripts"),  # WRONG
```

**AFTER:**

```python
from intellicrack.utils.core.plugin_paths import get_ghidra_scripts_dir

"-scriptPath",
str(get_ghidra_scripts_dir()),  # CORRECT
```

---

### 6. **`scripts/scanner/.scannerignore`**

**Lines 34-36** - Removed non-existent directories

**BEFORE:**

```
D:\Intellicrack\intellicrack\scripts\frida
D:\Intellicrack\intellicrack\scripts\ghidra
D:\Intellicrack\intellicrack\core\certificate\frida_scripts  # WRONG: shouldn't exist
D:\Intellicrack\intellicrack\plugins\frida_scripts           # WRONG: shouldn't exist
D:\Intellicrack\intellicrack\plugins\ghidra_scripts          # WRONG: shouldn't exist
```

**AFTER:**

```
D:\Intellicrack\intellicrack\scripts\frida   # CORRECT: only centralized location
D:\Intellicrack\intellicrack\scripts\ghidra  # CORRECT: only centralized location
```

---

## Impact

✅ **All Frida/Ghidra scripts now use centralized directories**  
✅ **No code will create duplicate script directories**  
✅ **Path resolution is consistent across entire codebase**  
✅ **Scanner exclusions updated to match reality**

---

## Verification

Run this to check for any remaining incorrect references:

```bash
rg "frida_scripts|ghidra_scripts" intellicrack/ --type py -l | grep -v plugin_paths.py
```

Should only find references in:

- Data structures (dict keys like `"frida_scripts"` for results)
- Comments/docstrings
- Variable names (not path construction)

---

**Conclusion:** All hardcoded paths eliminated. System now uses centralized
script management via `plugin_paths.py`.
