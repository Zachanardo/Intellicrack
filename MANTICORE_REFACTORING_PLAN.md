# Manticore to Angr Refactoring Plan

## Overview
Intellicrack is transitioning to Windows-only support and removing Manticore (Linux-only symbolic execution) in favor of Angr, which works cross-platform.

## Files Requiring Refactoring

### Core Implementation Files

#### 1. `intellicrack/core/analysis/concolic_executor_fixed.py`
**Changes Required:**
- Remove manticore imports and availability checks (lines 47-59)
- Delete `_explore_paths_manticore()` method (lines 174-208)
- Delete `_find_license_bypass_manticore()` method (lines 339-345)
- Update `explore_paths()` to only dispatch to angr or simconcolic
- Update `find_license_bypass()` to only use angr or simconcolic
- Remove MANTICORE_AVAILABLE from __all__ exports

**Angr Replacement:**
- All manticore path exploration logic is already implemented in `_explore_paths_angr()`
- License bypass logic is already in `_find_license_bypass_angr()`

#### 2. `intellicrack/core/analysis/concolic_executor.py`
**Changes Required:**
- Remove manticore imports (lines 31-44)
- Remove Manticore fallback class (lines 142-146)
- Delete `_setup_manticore_hooks()` method (line 1751)
- Remove LicenseBypassPlugin class for Manticore (lines 1564-1577)
- Update all manticore execution paths to use angr exclusively
- Remove manticore_available property and related checks

**Angr Replacement:**
- Use angr's SimProcedures instead of Manticore plugins
- Replace Manticore hooks with angr hooks
- Use angr's state exploration instead of Manticore's

#### 3. `intellicrack/core/analysis/simconcolic.py`
**Changes Required:**
- Remove Manticore and NativeManticore aliases (lines 393-395)
- Keep BinaryAnalyzer as the primary implementation

### Test Files

#### 1. `tests/unit/core/analysis/test_concolic_executor_fixed.py`
**Changes Required:**
- Remove MANTICORE_AVAILABLE import
- Delete test_manticore_available_property()
- Delete test_path_exploration_manticore_backend()
- Delete test_license_bypass_discovery_manticore()
- Delete test_manticore_backend_with_test_harness()
- Update engine priority tests to exclude manticore

#### 2. `tests/unit/core/analysis/test_concolic_executor.py`
**Changes Required:**
- Remove all manticore-specific test methods
- Update engine availability checks to only test angr and simconcolic

### Documentation Files

#### 1. `docs/INSTALLATION.md`
- Remove section "2. manticore (Secondary - Linux Only)" (lines 106-109)
- Remove troubleshooting section "5. Manticore not available on Windows" (lines 197-199)

#### 2. `docs/guides/SYMBOLIC_EXECUTION.md`
- Remove "### 2. manticore (Secondary Engine - Not Available on Windows)" section
- Remove manticore from execution_engines checks
- Update to state angr is the primary symbolic execution engine

#### 3. `docs/user-guide/getting-started.md`
- Remove manticore from pip install commands

#### 4. `docs/installation/setup.md`
- Remove "Concolic Execution (Manticore)" section
- Remove manticore from installation commands

#### 5. `docs/changelog.md`
- Remove manticore from optional dependencies list

### Utility Files

#### 1. `intellicrack/utils/dependencies.py`
- Remove "manticore": "Concolic execution" entry (line 139)

## Implementation Order

1. **Phase 1: Core Refactoring**
   - Update concolic_executor_fixed.py
   - Update concolic_executor.py
   - Update simconcolic.py
   - Update dependencies.py

2. **Phase 2: Test Updates**
   - Update all test files to remove manticore tests
   - Verify angr tests provide full coverage

3. **Phase 3: Documentation**
   - Update all documentation files
   - Remove manticore references
   - Emphasize angr as the primary symbolic execution engine

## Angr Feature Mapping

| Manticore Feature | Angr Equivalent |
|------------------|-----------------|
| Manticore() | angr.Project() |
| m.make_symbolic() | state.solver.BVS() |
| m.explore() | simgr.explore() |
| Plugin system | SimProcedures, hooks |
| State constraints | state.solver.add() |
| Path exploration | SimulationManager |
| Memory modeling | state.memory |
| Register access | state.regs |

## Benefits of Migration

1. **Windows Compatibility**: Angr works natively on Windows
2. **Better Documentation**: Angr has extensive documentation
3. **Active Development**: Angr is more actively maintained
4. **Performance**: Angr's engines are optimized for Windows
5. **Integration**: Better integration with other Intellicrack components

## Testing Strategy

After refactoring:
1. Run all symbolic execution tests with angr
2. Verify license bypass functionality
3. Test path exploration capabilities
4. Validate constraint solving
5. Ensure no regression in functionality

## Notes

- All manticore functionality is already duplicated in angr implementations
- The simconcolic module provides a lightweight alternative when angr is not available
- Focus on angr as the primary symbolic execution engine for Windows
