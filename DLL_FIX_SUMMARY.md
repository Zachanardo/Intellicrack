# Intel MKL DLL Loading Fix - Implementation Summary

**Date:** 2025-11-09
**Issue:** Entry point '?setNDRangeDescriptor@handler@_V1@sycl@@AEAAXV?$range@$02@2@W4mode@2@' not found in mkl_sycl_blas.5.dll
**Root Cause:** System Intel oneAPI installation DLLs loading instead of pixi environment DLLs

---

## Changes Implemented

###  1. Rust Launcher PATH Filtering (`intellicrack-launcher/src/environment.rs`)

**Location:** `configure_windows_dll_search_paths()` method (lines 278-334)

**What Changed:**
- Aggressive PATH filtering to **BLOCK all system Intel/oneAPI paths**
- Pixi environment DLL directories now have **absolute priority**
- Added logging to show how many Intel/oneAPI paths were blocked

**Key Implementation:**
```rust
let safe_system_paths: Vec<&str> = old_path
    .split(';')
    .filter(|p| {
        let p_lower = p.to_lowercase();
        !p_lower.contains("intel")
        && !p_lower.contains("oneapi")
        && !p_lower.contains("mkl")
    })
    .collect();
```

**Effect:** Prevents Windows DLL loader from finding system Intel oneAPI DLLs, forcing use of pixi environment versions.

---

### 2. IPEX Handler System Path Removal (`intellicrack/handlers/ipex_handler.py`)

**Location:** `_setup_ipex_dll_paths()` function (lines 77-103)

**What Changed:**
- **REMOVED** all system Intel oneAPI path discovery code (lines 102-167 deleted)
- Now uses **ONLY** pixi environment paths:
  - `site-packages/intel_extension_for_pytorch/bin`
  - `site-packages/torch/lib`
  - `site-packages/torch/bin`

**Effect:** Python code no longer adds system Intel oneAPI directories to DLL search path via `os.add_dll_directory()`.

---

### 3. Entry Point Error Detection (`scripts/safe_launch.py`)

**Location:** `validate_mkl_dlls()` function (lines 17-56)

**What Changed:**
- Added `mkl_sycl_blas.5.dll` to critical DLLs list
- Detect entry point errors specifically (error code 0xc0000139 / 127)
- Provide detailed diagnostic message explaining the issue

**Key Implementation:**
```python
error_code = getattr(e, 'winerror', None)
if error_code == 0xc0000139 or error_code == 127:
    return False, (
        f"Entry point not found in {dll_name}: {e}\n\n"
        f"This indicates ABI incompatibility - system Intel oneAPI DLLs may be loading...\n"
        ...
    )
```

**Effect:** Early detection of DLL version conflicts before GUI launch, with actionable error messages.

---

### 4. Crash Prevention in Rust Launcher (`intellicrack-launcher/src/lib.rs`)

**Location:** `launch()` method Python initialization (lines 118-167)

**What Changed:**
- Wrapped `PythonIntegration::initialize()` in safe error handling
- On failure, displays Windows MessageBox with diagnostic information
- Calls `std::process::exit(1)` to terminate cleanly instead of crashing

**Key Implementation:**
```rust
let mut python = match PythonIntegration::initialize() {
    Ok(py) => py,
    Err(e) => {
        #[cfg(target_os = "windows")]
        {
            // Show MessageBox with error details
            winapi::um::winuser::MessageBoxW(...);
        }
        std::process::exit(1);  // Clean exit, no crash
    }
};
```

**Effect:** Prevents PC crash when closing error dialog - process terminates gracefully.

---

### 5. New Diagnostic Tool (`scripts/dll_diagnostics.py`)

**Purpose:** Verify which DLLs are loaded and from where

**Features:**
- Checks PATH for Intel/oneAPI interference
- Uses Windows API to get actual loaded DLL paths
- Compares expected (pixi) vs actual load locations
- Provides recommendations for fixing PATH issues

**Usage:**
```bash
pixi run python scripts/dll_diagnostics.py
```

**Sample Output:**
```
[3] Critical DLL Loading Verification
    mkl_core.2.dll            : ✓ PIXI      : D:\Intellicrack\.pixi\envs\default\Library\bin\mkl_core.2.dll
    mkl_sycl_blas.5.dll       : ⚠️  SYSTEM   : C:\Program Files (x86)\Intel\oneAPI\mkl\2025.2\bin\mkl_sycl_blas.5.dll
```

---

## Testing the Fix

### Step 1: Rebuild Launcher

```bash
pixi run build-rust-launcher
```

**Expected:** Build completes with warnings about DLL copying (normal).

### Step 2: Run Diagnostic Tool

```bash
pixi run python scripts/dll_diagnostics.py
```

**Expected Output:**
- `✓ No system Intel paths found (GOOD)` under PATH analysis
- All critical DLLs show `✓ PIXI` status
- Recommendations section says "PATH configuration looks correct"

### Step 3: Test Launch

```bash
.\intellicrack-launcher\target\release\Intellicrack.exe
```

**Expected:**
- ✅ No entry point errors
- ✅ Application launches successfully
- ✅ If error occurs, MessageBox appears with diagnostic info (doesn't crash PC)

### Step 4: Verify PATH (Optional)

Inside Python session after launch:

```python
import os
print([p for p in os.environ["PATH"].split(";") if "intel" in p.lower() or "oneapi" in p.lower()])
# Should print: []  (empty list)
```

---

## Technical Details

### Windows DLL Search Order

The fix works by manipulating Windows DLL search order:

1. **Application directory** - ✅ Controlled by Rust launcher
2. **System32** - ⏭️ No Intel MKL there
3. **System directory** - ⏭️ Skipped via PATH filtering
4. **Current directory** - ⏭️ Minimal impact
5. **PATH directories** - ✅ Filtered to exclude Intel/oneAPI

### Why This Solution Works

1. **Rust launcher runs FIRST** - Sets up clean PATH before Python starts
2. **Python never sees system Intel paths** - PATH is pre-filtered
3. **IPEX doesn't add system paths** - Code removal prevents `os.add_dll_directory()` calls
4. **Early validation catches issues** - `safe_launch.py` tests before GUI
5. **Graceful failure** - MessageBox prevents crash loop

### Version Compatibility

The issue occurs because:
- **Pixi MKL:** 2025.2 with specific SYCL API version
- **System MKL:** Likely 2024.x or 2025.1 with different SYCL API
- **Symbol mismatch:** `setNDRangeDescriptor@handler@_V1@sycl` exists in pixi version, not system version

This fix ensures ONLY pixi MKL versions load, eliminating the version mismatch.

---

## Rollback Instructions

If the fix causes issues:

1. **Restore environment.rs:**
   ```bash
   git checkout intellicrack-launcher/src/environment.rs
   ```

2. **Restore ipex_handler.py:**
   ```bash
   git checkout intellicrack/handlers/ipex_handler.py
   ```

3. **Rebuild launcher:**
   ```bash
   pixi run build-rust-launcher
   ```

---

## Files Modified

1. `intellicrack-launcher/src/environment.rs` - PATH filtering
2. `intellicrack-launcher/src/lib.rs` - Crash prevention
3. `intellicrack/handlers/ipex_handler.py` - System path removal
4. `scripts/safe_launch.py` - Entry point error detection

## Files Created

1. `scripts/dll_diagnostics.py` - Diagnostic tool
2. `DLL_FIX_SUMMARY.md` - This document

---

## Next Steps

1. Test launcher with `Intellicrack.exe`
2. Run diagnostic tool to verify PATH filtering
3. If issues persist, check `dll_diagnostics.py` output
4. Monitor logs in `logs/intellicrack-launcher/` for PATH blocking messages

---

## Success Criteria

✅ Launcher starts without entry point errors
✅ No PC crash when error dialog appears
✅ System Intel oneAPI paths blocked from PATH
✅ IPEX imports successfully
✅ Diagnostic tool shows all DLLs loading from pixi environment

