# Intellicrack CLI Import Analysis

This document analyzes the imports in `scripts/intellicrack_cli.py` and identifies what exists vs. what's missing in the codebase.

## Core Analysis Module Imports (intellicrack.core.analysis)

### CLI Expects:
```python
from intellicrack.core.analysis import (
    SymbolicExecutionEngine,
    ConcolicExecutionEngine, 
    TaintAnalysisEngine,
    ROPChainGenerator,
    CFGExplorer,
    VulnerabilityEngine,
    MultiFormatBinaryAnalyzer,
    BinarySimilaritySearch,
    IncrementalAnalysisManager
)
```

### What Actually Exists:
```python
# From __init__.py:
SymbolicExecutionEngine ✅
ConcolicExecutionEngine ✅
TaintAnalysisEngine ✅
ROPChainGenerator ✅
CFGExplorer ✅
VulnerabilityEngine ✅
MultiFormatBinaryAnalyzer ✅
IncrementalAnalysisManager ✅
SimilaritySearcher ❌ (CLI expects BinarySimilaritySearch)
```

**Issue**: CLI expects `BinarySimilaritySearch` but module exports `SimilaritySearcher`

## Network Module Imports (intellicrack.core.network)

### CLI Expects:
```python
from intellicrack.core.network import (
    NetworkTrafficAnalyzer,
    ProtocolFingerprinter,
    LicenseServerEmulator,
    SSLInterceptor,
    CloudLicenseHooker
)
```

### What Actually Exists:
```python
# From __init__.py:
TrafficAnalyzer ❌ (CLI expects NetworkTrafficAnalyzer)
ProtocolFingerprinter ✅
LicenseServerEmulator ✅
SSLInterceptor ✅
CloudLicenseHooker ✅
```

**Issue**: CLI expects `NetworkTrafficAnalyzer` but module exports `TrafficAnalyzer`

## Patching Module Imports (intellicrack.core.patching)

### CLI Expects:
```python
from intellicrack.core.patching import (
    MemoryPatcher,
    PayloadGenerator,
    WindowsActivator,
    AdobeInjector
)
```

### What Actually Exists:
```python
# From __init__.py:
PayloadGenerator ✅
WindowsActivator ✅
AdobeInjector ✅
generate_launcher_script ❌ (CLI expects MemoryPatcher class)
setup_memory_patching ❌ (CLI expects MemoryPatcher class)
```

**Issue**: CLI expects `MemoryPatcher` class but module only has functions

## Protection Bypass Module Imports (intellicrack.core.protection_bypass)

### CLI Expects:
```python
from intellicrack.core.protection_bypass import (
    TPMBypass,
    VMBypass,
    DongleEmulator
)
```

### What Actually Exists:
```python
# From __init__.py:
TPMAnalyzer ❌ (CLI expects TPMBypass)
VMDetector ❌ (CLI expects VMBypass)  
HardwareDongleEmulator ❌ (CLI expects DongleEmulator)
```

**Issue**: All class names are different between CLI expectations and actual exports

## Processing Module Imports (intellicrack.core.processing)

### CLI Expects:
```python
from intellicrack.core.processing import (
    DistributedAnalysisManager,
    GPUAccelerator,
    QEMUSystemEmulator,
    MemoryOptimizedLoader
)
```

### What Actually Exists:
**Need to check these modules individually**

## AI Module Imports (intellicrack.ai)

### CLI Expects:
```python
from intellicrack.ai import (
    MLVulnerabilityPredictor,
    ModelManager,
    AITools
)
```

### What Actually Exists:
```python
# From __init__.py:
VulnerabilityPredictor ❌ (CLI expects MLVulnerabilityPredictor)
ModelManager ✅
AIAssistant ❌ (CLI expects AITools)
```

**Issue**: Class names don't match CLI expectations

## Runner Functions Imports (intellicrack.utils.runner_functions)

### CLI Expects (from wildcard import):
Many functions like:
- `run_comprehensive_analysis`
- `run_comprehensive_protection_scan`
- `run_detect_packing`
- `run_weak_crypto_detection`
- `run_generate_patch_suggestions`
- `run_section_analysis`
- `run_import_export_analysis`
- `apply_patches`
- `generate_hwid_spoof_config`
- `run_ml_similarity_search`
- `run_ghidra_analysis`
- `run_radare2_analysis`

### What Actually Exists:
Many runner functions exist but some are missing. Need detailed check.

## Utility Module Imports (intellicrack.utils)

### CLI Expects:
```python
from intellicrack.utils import (
    protection_detection,
    protection_utils,
    exploitation,
    system_utils
)
```

### What Actually Exists:
**Need to check if these modules exist**

## Summary of Major Issues

1. **Class Name Mismatches**: Many class names in CLI don't match actual exports
2. **Missing Classes**: Some expected classes don't exist (like MemoryPatcher)
3. **Missing Functions**: Some runner functions expected by CLI are missing
4. **Import Aliases**: Some modules use different aliases than CLI expects

## Required Fixes

### Option 1: Update CLI to match existing code
- Change `BinarySimilaritySearch` → `SimilaritySearcher`
- Change `NetworkTrafficAnalyzer` → `TrafficAnalyzer`
- Change `MLVulnerabilityPredictor` → `VulnerabilityPredictor`
- Change `TPMBypass` → `TPMAnalyzer`
- Change `VMBypass` → `VMDetector`
- Change `DongleEmulator` → `HardwareDongleEmulator`
- Change `AITools` → `AIAssistant`
- Add proper MemoryPatcher class or use existing functions

### Option 2: Update codebase to match CLI expectations
- Add aliases in __init__.py files to match CLI expectations
- Create missing classes where needed
- Add missing runner functions

### Option 3: Hybrid approach
- Fix critical missing functions
- Add aliases for name mismatches
- Update CLI only where major architectural changes are needed

## Recommendation

**Option 1 (Update CLI)** is recommended because:
1. The existing codebase is working and verified
2. CLI is new and not yet in production use
3. Changing import names is safer than changing core functionality
4. Preserves the verified modular architecture

The CLI should be updated to match the actual codebase structure rather than trying to retrofit the codebase to match unverified CLI expectations.