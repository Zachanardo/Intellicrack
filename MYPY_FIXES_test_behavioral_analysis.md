# mypy --strict Fixes for test_behavioral_analysis.py

## Summary

All mypy --strict errors have been fixed in `tests/core/analysis/test_behavioral_analysis.py`.

## Changes Made

### 1. Import Fallback Pattern (Lines 22-55)
**BEFORE:**
```python
try:
    from intellicrack.core.analysis.behavioral_analysis import (
        AntiAnalysisDetector,
        ...
    )
    AVAILABLE = True
except ImportError:
    AntiAnalysisDetector = None  # ERROR: Incompatible types
    AVAILABLE = False
```

**AFTER:**
```python
AntiAnalysisDetector: type[Any] | None
APIHookingFramework: type[Any] | None
BehavioralAnalyzer: type[Any] | None
HookPoint: type[Any] | None
MonitorEvent: type[Any] | None
QEMUConfig: type[Any] | None
QEMUController: type[Any] | None
create_behavioral_analyzer: Any
run_behavioral_analysis: Any

try:
    from intellicrack.core.analysis.behavioral_analysis import (
        AntiAnalysisDetector,
        ...
    )
    AVAILABLE = True
except ImportError:
    AntiAnalysisDetector = None
    ...
    AVAILABLE = False
```

### 2. Generator Type Annotation (Line 69)
**BEFORE:**
```python
@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)
```

**AFTER:**
```python
@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)
```

### 3. AntiAnalysisDetector API Corrections
- Changed from non-existent `detect_anti_debug(binary_data)` to actual `scan(process_id)` method
- Added assertions: `assert AntiAnalysisDetector is not None`
- Tests now use `psutil.Process().pid` instead of binary data

### 4. HookPoint API Corrections (Lines 160-168)
**BEFORE:**
```python
hook = HookPoint(
    function_name="CreateFileW",  # WRONG field
    module_name="kernel32.dll",   # WRONG field
    hook_type="pre",              # WRONG field
    callback=None,
)
```

**AFTER:**
```python
assert HookPoint is not None
hook = HookPoint(
    module="kernel32.dll",    # CORRECT field
    function="CreateFileW",   # CORRECT field
    on_enter=None,           # CORRECT field
    on_exit=None,
)
```

### 5. APIHookingFramework Method Corrections
**BEFORE:**
```python
assert hasattr(framework, "install_hooks")
assert hasattr(framework, "remove_hooks")
assert hasattr(framework, "get_hooked_calls")
```

**AFTER:**
```python
assert hasattr(framework, "add_hook")
assert hasattr(framework, "remove_hook")
assert hasattr(framework, "enable_hook")
```

### 6. QEMUConfig API Corrections (Lines 212-232)
**BEFORE:**
```python
config = QEMUConfig(
    arch="x86_64",      # WRONG - no such field
    memory_size=512,    # WRONG - should be str, not int
    enable_kvm=False,
    snapshot=True,      # WRONG - no such field
)
```

**AFTER:**
```python
assert QEMUConfig is not None
config = QEMUConfig(
    memory_size="512M",  # CORRECT - str type
    enable_kvm=False,
)
```

### 7. MonitorEvent API Corrections (Lines 237-248)
**BEFORE:**
```python
event = MonitorEvent(
    timestamp=time.time(),
    event_type="api_call",
    function_name="CreateFileW",  # WRONG field
    parameters={...},              # WRONG field
    return_value=0,                # WRONG field
)
```

**AFTER:**
```python
assert MonitorEvent is not None
event = MonitorEvent(
    timestamp=time.time(),
    event_type="api_call",
    process_id=1234,     # CORRECT field
    thread_id=5678,      # CORRECT field
    data={...},          # CORRECT field
)
```

### 8. BehavioralAnalyzer Instantiation
**BEFORE:**
```python
analyzer = BehavioralAnalyzer(binary_path=notepad_path)  # str
```

**AFTER:**
```python
assert BehavioralAnalyzer is not None
analyzer = BehavioralAnalyzer(binary_path=Path(notepad_path))  # Path
```

### 9. Method Parameter Corrections
**BEFORE:**
```python
result = analyzer.run_analysis(timeout=5)  # WRONG parameter name
```

**AFTER:**
```python
result = analyzer.run_analysis(duration=5)  # CORRECT parameter name
```

### 10. Type Annotations Added
- Added explicit type annotations for all list/dict variables:
  - `results: list[tuple[str, dict[str, Any]]] = []`
  - `errors: list[tuple[str, str]] = []`
  - `threads: list[threading.Thread] = []`

### 11. Assertion Guards
- Added `assert ClassName is not None` before every instantiation of potentially-None classes
- This satisfies mypy's strict mode while maintaining runtime safety

## Files Modified
- `D:\Intellicrack\tests\core\analysis\test_behavioral_analysis.py`

## Validation
All changes ensure:
1. NO `type: ignore` comments
2. ALL functions have proper type annotations
3. ALL attribute access matches actual API from `behavioral_analysis.py`
4. Generator fixtures properly annotated as `Generator[T, None, None]`
5. Import fallback pattern uses pre-declared type annotations
6. All instantiations guarded with assertions

## Result
✅ File is now fully mypy --strict compliant
✅ All API mismatches corrected
✅ All type annotations complete
✅ No placeholder or incorrect implementations
