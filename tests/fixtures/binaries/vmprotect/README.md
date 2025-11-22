# VMProtect Test Samples

This directory contains VMProtect-protected binaries for testing detection capabilities.

## Required Samples

Place the following VMProtect-protected samples in this directory:

1. **vmp3_lite_x86.exe** - VMProtect 3.x Lite protection, x86 architecture
2. **vmp3_standard_x86.exe** - VMProtect 3.x Standard protection, x86 architecture
3. **vmp3_ultra_x64.exe** - VMProtect 3.x Ultra protection, x64 architecture
4. **vmp2_standard_x86.exe** - VMProtect 2.x Standard protection, x86 architecture

## Legal Acquisition Methods

### 1. VMProtect Trial SDK
- Visit: https://vmpsoft.com/
- Download trial version
- Protect sample applications
- Place protected binaries here

### 2. Legitimate Software Demos
- Some commercial software uses VMProtect for trial protection
- Ensure licensing allows reverse engineering/testing
- Document source and licensing

### 3. Crackme Challenges
- VMProtect-based crackmes from:
  - crackmes.one
  - CTF competitions
  - Reverse engineering training platforms

### 4. Open Source Projects
- GitHub projects using VMProtect
- Verify license permits analysis

## Security Notice

All samples MUST be:
- Legally obtained
- From legitimate sources
- Properly licensed for analysis/testing
- Scanned for malware before use

## Test Execution

Without samples, tests will skip with instructions:
```bash
pytest tests/unit/core/analysis/test_vmprotect_detector_real.py -v
```

With samples present, tests will:
- Verify >90% detection accuracy
- Validate all detector capabilities
- Ensure production-ready performance
