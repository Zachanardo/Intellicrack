# Fix Plan: fix_types.py and TypeFix.ps1 Issues

## Overview
Addressing 14 valid/partially valid claims about robustness issues in the type fixer scripts.

---

## CATEGORY A: Validation Issues (Claims 1-4)

### Claim 1 & 2: Import Validation Dangerous & Broken

**Problem**: Lines 109-139 execute full module code via `spec.loader.exec_module()`, which:
- Fails on relative imports (no package context)
- Executes PyQt/Torch/Frida side effects
- Wrong cwd for deeply nested files

**Fix**: Remove the module execution phase entirely. Keep validation but cap at static checks only:
- AST parsing for syntax (already exists, lines 63-66)
- Class/method structure comparison (already exists, lines 68-107)
- **DELETE** lines 109-139 (the `exec_module` import test)

```python
# REMOVE the entire import validation block (lines 109-139)
# validate_python_file() becomes AST-only:
def validate_python_file(file_path: str, original_content: str | None = None) -> tuple[bool, str]:
    # 1. AST parse (syntax check)
    # 2. Class structure check (orphaned methods)
    # NO exec_module - stop here
    return True, ""
```

### Claim 3: cwd Calculation Wrong

**Problem**: `Path(file_path).parent.parent.parent` is hardcoded, fails for files at depth != 3.

**Fix**: Calculate project root dynamically:
```python
def get_project_root(file_path: str) -> Path:
    """Find project root by looking for pyproject.toml or .git"""
    current = Path(file_path).resolve().parent
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / ".git").exists():
            return current
        current = current.parent
    return Path.cwd()
```

### Claim 4: Class Structure Check Limited

**Problem**: Only detects methods de-indented to module level, not deleted/moved methods.

**Fix**: Expand validation:
```python
# Add checks for:
# 1. Classes deleted entirely
# 2. Method count decreased significantly (>50% methods lost)
# 3. New module-level functions that weren't there before
if class_name not in new_classes:
    return False, f"Class '{class_name}' was deleted"

if len(new_classes.get(class_name, set())) < len(methods) * 0.5:
    return False, f"Class '{class_name}' lost >50% of methods"
```

---

## CATEGORY B: Rollback/Recovery Issues (Claims 5-6)

### Claim 5: Non-Zero Exit Leaves Partial Edits

**Problem**: `original_content` captured but never restored on CLI failure.

**Fix**: Add content restoration before returning failure:
```python
if result is None or result.returncode != 0:
    # Restore original content on failure
    if original_content is not None:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_content)
        except Exception:
            pass  # Best effort
    return {...}
```

### Claim 6: git checkout Rollbacks Fail Silently

**Problem**: No `--` separator, errors swallowed, untracked files not handled.

**Fix**: Robust rollback function:
```python
def rollback_file(file_path: str, original_content: str | None, cwd: str) -> bool:
    """Rollback file changes with multiple fallback strategies."""
    # Strategy 1: git checkout with proper syntax
    result = subprocess.run(
        ["git", "checkout", "--", file_path],
        cwd=cwd,
        capture_output=True,
    )
    if result.returncode == 0:
        return True

    # Strategy 2: Write original content directly
    if original_content is not None:
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(original_content)
            return True
        except Exception:
            pass

    return False
```

---

## CATEGORY C: Regression Detection (Claims 7-8)

### Claim 7: Single-File Mypy Only

**Problem**: Cross-file regressions undetected until next iteration.

**Fix**: Accept this limitation but add documentation. Full mypy per file is too expensive. The iterative approach catches cross-file issues eventually. Add comment:
```python
# NOTE: Single-file mypy check. Cross-file regressions detected in next iteration.
```

### Claim 8: Regression Threshold Too Permissive

**Problem**: Requires BOTH `>2×` AND `>+20`. Small regressions pass.

**Fix**: Use OR logic with tight thresholds (user-specified):
```python
# OLD: if errors_after > errors_before * 2 and errors_after > errors_before + 20:
# NEW: Revert on ANY meaningful increase
if errors_after > errors_before + 2 or errors_after >= errors_before * 1.25:
    rollback_file(file_path, original_content, cwd)
    return {"success": False, "error": f"Regression: {errors_before} -> {errors_after}"}
```
Rationale: Tolerates ±2 for mypy noise but catches any real increase.

---

## CATEGORY D: Input Validation (Claims 9-10)

### Claim 9: --errors-per-file Not Validated

**Problem**: 0, negative, or huge values cause issues.

**Fix**: Add validation in argparse:
```python
parser.add_argument(
    "--errors-per-file", type=int, default=100,
    choices=range(10, 501),
    metavar="10-500",
    help="Maximum errors to show Claude per file (10-500, default: 100)"
)
```

Or custom validator:
```python
def validate_errors_per_file(value: str) -> int:
    ivalue = int(value)
    if not 10 <= ivalue <= 500:
        raise argparse.ArgumentTypeError(f"Must be 10-500, got {ivalue}")
    return ivalue
```

### Claim 10: No Model Validation

**Problem**: Typos like `--model sonnet5` propagate to workers.

**Fix**: Add startup model test (user confirmed ~5s delay is acceptable):
```python
def validate_model(model: str) -> bool:
    """Test model with trivial prompt at startup."""
    print(f"Validating model '{model}'...", end=" ", flush=True)
    try:
        result = subprocess.run(
            ["claude", "-p", "--model", model, "--max-turns", "1"],
            input="Say OK",
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print("OK")
            return True
        print("FAILED")
        return False
    except subprocess.TimeoutExpired:
        print("TIMEOUT")
        return False

# In main(), after claude --version check:
if not validate_model(args.model):
    print(f"ERROR: Model '{args.model}' is invalid or unavailable")
    print("Valid models: sonnet, opus, haiku, or full slugs like claude-sonnet-4-5-20250929")
    sys.exit(1)
```

---

## CATEGORY E: Operational Issues (Claims 11-12)

### Claim 11: No Adaptive Pool Backoff

**Problem**: Rate limits hammer same path with no pool-level backoff.

**Fix**: Batch-level failure tracking with dispatcher pause (user-specified pattern):
```python
class BatchFailureTracker:
    def __init__(self, worker_timeout: int):
        self.worker_timeout = worker_timeout
        self.batch_results: list[bool] = []  # True=success, False=transient failure
        self.lock = threading.Lock()

    def record_result(self, success: bool, transient_error: bool = False) -> None:
        with self.lock:
            # Only track transient errors (rate-limit, auth, CLI crash) not logic failures
            self.batch_results.append(success or not transient_error)

    def should_pause_dispatcher(self) -> tuple[bool, int]:
        """Check if >=50% of last batch had transient failures."""
        with self.lock:
            if len(self.batch_results) < 2:
                return False, 0
            failure_rate = self.batch_results.count(False) / len(self.batch_results)
            if failure_rate >= 0.5:
                pause_time = min(self.worker_timeout, 120)
                self.batch_results.clear()  # Reset for next batch
                return True, pause_time
            return False, 0

    def is_healthy(self) -> bool:
        """Check if success rate >= 70% (can resume normal cadence)."""
        with self.lock:
            if len(self.batch_results) < 3:
                return True
            success_rate = self.batch_results.count(True) / len(self.batch_results)
            if success_rate >= 0.7:
                self.batch_results.clear()
                return True
            return False
```

Usage in `_process_files_batch()`:
- After each future completes, call `tracker.record_result()`
- Before submitting next batch, check `should_pause_dispatcher()`
- Resume normal cadence when `is_healthy()` returns True

### Claim 12: Raw ANSI Without Rich

**Problem**: `git diff --color=always` prints raw escape codes in non-Rich mode.

**Fix**: Conditional color:
```python
color_flag = "--color=always" if RICH_AVAILABLE else "--color=never"
git_diff_result = subprocess.run(
    ["git", "diff", color_flag, file_path],
    ...
)
```

---

## CATEGORY F: PowerShell Issues (Claims 14-15)

### Claim 14: No Pixi Error Handling

**Problem**: Missing pixi causes silent failure.

**Fix**: Add pixi check:
```powershell
# Add before Start-TypeFixer:
$pixiPath = Get-Command pixi -ErrorAction SilentlyContinue
if (-not $pixiPath) {
    Write-Host "  ERROR: 'pixi' not found in PATH" -ForegroundColor Red
    Write-Host "  Install pixi: https://pixi.sh" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Press any key to exit..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
```

### Claim 15: No Profile/Key Support

**Problem**: Single --model only, no profile selection.

**Fix**: Add optional profile parameter:
```powershell
# Add to $cmdArgs if profile selected:
function Select-Profile {
    Write-Host ""
    Write-Host "  Claude profile (optional):" -ForegroundColor Yellow
    Write-Host "  -------------------------------------" -ForegroundColor DarkGray
    Write-Host "    Leave empty for default" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "  Profile []"
    if ([string]::IsNullOrWhiteSpace($choice)) { return $null }
    return $choice
}

# In Start-TypeFixer:
if ($null -ne $Profile) {
    $cmdArgs += @("--profile", $Profile)
}
```

---

## Implementation Order (by severity)

1. **Critical (data loss prevention)**:
   - Claim 5: Restore content on CLI failure
   - Claim 6: Robust rollback with `--` separator and fallback to original_content

2. **High (validation reliability)**:
   - Claims 1-2: Remove exec_module import test (keep AST + class structure only)
   - Claim 3: Fix cwd calculation with dynamic project root detection
   - Claim 4: Expand class structure checks (deleted classes, >50% method loss)

3. **Medium (correctness)**:
   - Claim 8: Use OR logic: `errors_after > errors_before + 2 or >= 1.25×`
   - Claim 9: Validate errors-per-file range (10-500)
   - Claim 10: Test model at startup with trivial prompt

4. **Low (quality of life)**:
   - Claim 11: Batch failure tracking with 50%/70% thresholds
   - Claim 12: Conditional ANSI colors (`--color=never` without Rich)
   - Claim 14: Pixi existence check in PowerShell
   - Claim 15: Optional profile support
   - Claim 7: Document single-file mypy limitation

---

## Files to Modify

1. `scripts/fix_types.py` - All Python fixes
2. `TypeFix.ps1` - PowerShell launcher fixes

## Estimated Changes

- ~200 lines modified/added in fix_types.py (including BatchFailureTracker class)
- ~40 lines modified/added in TypeFix.ps1
