# Extraction Functionality Findings

## Issue
Extraction fails on Windows with error:
```
Failed to create symlink: A required privilege is not held by the client. (os error 1314)
```

## Root Cause
- Binwalk v3 (Rust binary) attempts to create symlinks during extraction
- Windows requires administrator privileges to create symlinks
- This is a binwalk v3 binary limitation, not a Python wrapper issue

## Validation Results

### Signature Detection: ✓ WORKING
- All real binary tests passed (6/6)
- MSI files: Detected CAB and PNG signatures
- JAR files: Detected ZIP signatures
- EXE files: Detected PE headers, copyright text, PNG images
- DLL files: Detected PE headers, CRC tables
- All signature types correctly identified

### Extraction: ⚠ WINDOWS LIMITATION
- Requires administrator privileges on Windows
- This is a binwalk v3 binary issue (symlink creation)
- Works on Linux/macOS without issue
- Not a blocker for package publication

## Recommendation
Document in README that extraction on Windows requires:
1. Run Python as administrator, OR
2. Enable Developer Mode (which grants symlink privileges), OR
3. Use WSL/Linux for extraction workflows

The Python wrapper correctly passes extraction flags to the binary.
The issue is in the binwalk v3 binary's Windows implementation.
